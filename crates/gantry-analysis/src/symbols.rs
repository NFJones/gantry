//! Module graph construction, package symbols, imports, and name resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::portable::{DiagnosticCategory, DiagnosticSeverity};
use gantry_core::source::{
    DiagnosticCode, DiagnosticMetadata, DiagnosticPhase, RelatedSpan, SourceCounters, SourceSpan,
    StructuredDiagnostic,
};
use gantry_frontend::{
    CompletedSyntaxPhase, ModuleResolutionIssueKind, NodeId, PackageSyntaxStatus, ParsedSource,
    Punctuation, SyntaxForm, SyntaxTree, TokenKind,
};
use gantry_ir::CanonicalPath;

use crate::model::{
    AgentName, AnalysisError, AnalysisStatus, Module, ModuleId, PackageStructure,
    ResolvedReference, Symbol, SymbolId, SymbolKind,
};
use crate::security::{IdentifierSecurity, classify};

/// One module body associated with its canonical path and source tree.
#[derive(Clone)]
struct ModuleContext {
    path: String,
    parent: Option<String>,
    source_index: usize,
    node: NodeId,
    span: SourceSpan,
}

/// One authored package-item declaration before duplicate validation.
#[derive(Clone)]
struct ItemDraft {
    module_path: String,
    name: Arc<str>,
    kind: SymbolKind,
    path: CanonicalPath,
    span: SourceSpan,
}

/// Source-level path root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathRoot {
    Relative,
    Crate,
    SelfModule,
    Super(u32),
}

/// One exact parsed source path with its final identifier span.
#[derive(Clone)]
struct PathSpec {
    root: PathRoot,
    segments: Vec<Arc<str>>,
    span: SourceSpan,
    final_span: SourceSpan,
}

/// One `use` declaration collected before order-independent resolution.
#[derive(Clone)]
struct ImportDraft {
    module: ModuleId,
    path: PathSpec,
}

/// One identifier declaration and its lookup namespace.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct BindingRecord {
    namespace: String,
    name: Arc<str>,
    span: SourceSpan,
}

/// Internal package namespace assembled before body analysis.
struct CollectedPackage {
    modules: Vec<Module>,
    contexts: Vec<ModuleContext>,
    module_ids: BTreeMap<String, ModuleId>,
    symbols: Vec<Symbol>,
    local_names: BTreeMap<ModuleId, BTreeMap<Arc<str>, SymbolId>>,
    symbol_modules: BTreeMap<SymbolId, ModuleId>,
    bindings: Vec<BindingRecord>,
}

/// Analyzes syntax-valid package structure without performing type analysis or
/// constructing canonical execution artifacts.
pub fn analyze_package_structure(
    phase: &CompletedSyntaxPhase,
) -> Result<PackageStructure, AnalysisError> {
    if phase.status() != PackageSyntaxStatus::Valid {
        return Err(AnalysisError::SyntaxInvalid);
    }

    let mut diagnostics = Vec::new();
    collect_module_resolution_diagnostics(phase, &mut diagnostics)?;
    let contexts = collect_module_contexts(phase.parsed_sources(), &mut diagnostics)?;
    let mut package = collect_package_items(phase.parsed_sources(), contexts, &mut diagnostics)?;
    let imports = collect_imports(phase.parsed_sources(), &package, &mut diagnostics)?;
    let (import_names, import_bindings, import_path_spans) =
        resolve_imports(&package, &imports, &mut diagnostics)?;
    package.bindings.extend(import_bindings);

    let references = resolve_references(
        phase.parsed_sources(),
        &package,
        &import_names,
        &import_path_spans,
        &mut diagnostics,
    )?;
    let mut bindings = std::mem::take(&mut package.bindings);
    let agents = collect_agents(
        phase.parsed_sources(),
        &package,
        &mut diagnostics,
        &mut bindings,
    )?;
    collect_member_and_scope_bindings(
        phase.parsed_sources(),
        &package,
        &import_names,
        &mut diagnostics,
        &mut bindings,
    )?;
    check_member_collisions(&bindings, &mut diagnostics)?;
    check_all_identifier_security(phase.parsed_sources(), &mut diagnostics)?;
    check_confusable_bindings(&bindings, &mut diagnostics)?;
    package.bindings = bindings;

    finish_structure(
        package,
        references,
        agents,
        diagnostics,
        phase.snapshot().counters().clone(),
    )
}

/// Converts frontend-observed file candidate outcomes into analyzer-owned
/// module-validity diagnostics without re-reading package paths.
fn collect_module_resolution_diagnostics(
    phase: &CompletedSyntaxPhase,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    for issue in phase.module_resolution_issues() {
        let module_path = if issue.directory().is_empty() {
            format!("crate::{}", issue.name())
        } else {
            format!(
                "crate::{}::{}",
                issue.directory().replace('/', "::"),
                issue.name()
            )
        };
        match issue.kind() {
            ModuleResolutionIssueKind::Missing => diagnostics.push(diagnostic(
                "missing-module-source",
                DiagnosticSeverity::Error,
                DiagnosticCategory::NameResolution,
                "a file module declaration has no permitted source candidate",
                Some(issue.span().clone()),
                Vec::new(),
                [("canonical_path", safe_qualified_name(&module_path))],
            )?),
            ModuleResolutionIssueKind::Ambiguous { flat, nested } => {
                diagnostics.push(diagnostic(
                    "ambiguous-module-resolution",
                    DiagnosticSeverity::Error,
                    DiagnosticCategory::NameResolution,
                    "both permitted file module candidates exist",
                    Some(issue.span().clone()),
                    Vec::new(),
                    [
                        ("canonical_path", safe_qualified_name(&module_path)),
                        ("flat_candidate", safe_package_path(flat.as_str())),
                        ("nested_candidate", safe_package_path(nested.as_str())),
                    ],
                )?);
            }
        }
    }
    Ok(())
}

/// Derives every file and inline module context using explicit work stacks.
fn collect_module_contexts(
    parsed_sources: &[ParsedSource],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Vec<ModuleContext>, AnalysisError> {
    let mut contexts = Vec::new();
    for (source_index, source) in parsed_sources.iter().enumerate() {
        let base = module_path_from_source(source.source().package_path().as_str())?;
        let root = source
            .tree()
            .node(source.tree().root())
            .ok_or(AnalysisError::Invariant)?;
        let parent = parent_module_path(&base);
        contexts.push(ModuleContext {
            path: base.clone(),
            parent,
            source_index,
            node: source.tree().root(),
            span: root.span().clone(),
        });

        let mut work = vec![(source.tree().root(), base)];
        while let Some((module_node, module_path)) = work.pop() {
            let node = source
                .tree()
                .node(module_node)
                .ok_or(AnalysisError::Invariant)?;
            for child in node.children().iter().rev().copied() {
                let child_node = source.tree().node(child).ok_or(AnalysisError::Invariant)?;
                if !matches!(child_node.form(), SyntaxForm::ModuleDeclaration)
                    || is_file_module(source.tree(), child)?
                {
                    continue;
                }
                let (name, _) = declaration_name(source.tree(), child)?;
                let path = join_module_path(&module_path, &name);
                contexts.push(ModuleContext {
                    path: path.clone(),
                    parent: Some(module_path.clone()),
                    source_index,
                    node: child,
                    span: child_node.span().clone(),
                });
                work.push((child, path));
            }
        }
    }

    contexts.sort_by(|left, right| {
        left.path
            .as_bytes()
            .cmp(right.path.as_bytes())
            .then_with(|| left.span.cmp(&right.span))
    });
    let mut unique = Vec::new();
    for group in equal_runs(&contexts, |context| context.path.as_str()) {
        if group.len() > 1 {
            let first = &contexts[group.start];
            for duplicate in &contexts[group.start + 1..group.end] {
                diagnostics.push(diagnostic(
                    "duplicate-module-resolution",
                    DiagnosticSeverity::Error,
                    DiagnosticCategory::NameResolution,
                    "one canonical module path was resolved more than once",
                    Some(duplicate.span.clone()),
                    vec![RelatedSpan {
                        label: Arc::from("first resolution"),
                        span: first.span.clone(),
                    }],
                    [("canonical_path", safe_qualified_name(&first.path))],
                )?);
            }
        }
        unique.push(contexts[group.start].clone());
    }
    if unique.first().is_none_or(|context| context.path != "crate") {
        return Err(AnalysisError::Invariant);
    }
    Ok(unique)
}

/// Assigns dense module and symbol identifiers in canonical path order.
fn collect_package_items(
    parsed_sources: &[ParsedSource],
    contexts: Vec<ModuleContext>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<CollectedPackage, AnalysisError> {
    let mut module_ids = BTreeMap::new();
    for (index, context) in contexts.iter().enumerate() {
        let value = u32::try_from(index).map_err(|_| AnalysisError::Invariant)?;
        module_ids.insert(context.path.clone(), ModuleId::new(value));
    }

    let mut modules = Vec::with_capacity(contexts.len());
    for context in &contexts {
        let id = *module_ids
            .get(&context.path)
            .ok_or(AnalysisError::Invariant)?;
        let parent = context
            .parent
            .as_ref()
            .and_then(|path| module_ids.get(path))
            .copied();
        if context.path != "crate" && parent.is_none() {
            diagnostics.push(diagnostic(
                "missing-parent-module",
                DiagnosticSeverity::Error,
                DiagnosticCategory::NameResolution,
                "a discovered module has no containing module",
                Some(context.span.clone()),
                Vec::new(),
                [("canonical_path", safe_qualified_name(&context.path))],
            )?);
        }
        modules.push(Module {
            id,
            path: Arc::from(context.path.as_str()),
            parent,
            span: context.span.clone(),
        });
    }
    diagnose_module_cycles(&modules, diagnostics)?;

    let mut drafts = Vec::new();
    let mut bindings = Vec::new();
    for context in &contexts {
        let source = parsed_sources
            .get(context.source_index)
            .ok_or(AnalysisError::Invariant)?;
        let module = *module_ids
            .get(&context.path)
            .ok_or(AnalysisError::Invariant)?;
        let tree = source.tree();
        let node = tree.node(context.node).ok_or(AnalysisError::Invariant)?;
        for child in node.children().iter().copied() {
            let Some(kind) = item_kind(tree.node(child).ok_or(AnalysisError::Invariant)?.form())
            else {
                continue;
            };
            let (name, span) = declaration_name(tree, child)?;
            let path_text = join_module_path(&context.path, &name);
            let path = CanonicalPath::new(&path_text).map_err(|_| AnalysisError::Invariant)?;
            drafts.push(ItemDraft {
                module_path: context.path.clone(),
                name: name.clone(),
                kind,
                path,
                span: span.clone(),
            });
            bindings.push(BindingRecord {
                namespace: format!("items:{}", context.path),
                name,
                span,
            });
            let _ = module;
        }
    }

    drafts.sort_by(|left, right| {
        left.path
            .as_str()
            .as_bytes()
            .cmp(right.path.as_str().as_bytes())
            .then_with(|| left.span.cmp(&right.span))
    });
    let mut unique_drafts = Vec::new();
    for group in equal_runs(&drafts, |draft| draft.path.as_str()) {
        let first = &drafts[group.start];
        if group.len() > 1 {
            for duplicate in &drafts[group.start + 1..group.end] {
                diagnostics.push(diagnostic(
                    "duplicate-item",
                    DiagnosticSeverity::Error,
                    DiagnosticCategory::NameResolution,
                    "an item name is duplicated in one module namespace",
                    Some(duplicate.span.clone()),
                    vec![RelatedSpan {
                        label: Arc::from("first declaration"),
                        span: first.span.clone(),
                    }],
                    [("canonical_path", safe_qualified_name(first.path.as_str()))],
                )?);
            }
        } else {
            unique_drafts.push(first.clone());
        }
    }

    let mut symbols = Vec::with_capacity(unique_drafts.len());
    let mut local_names = BTreeMap::<ModuleId, BTreeMap<Arc<str>, SymbolId>>::new();
    let mut symbol_modules = BTreeMap::new();
    for (index, draft) in unique_drafts.into_iter().enumerate() {
        let value = u32::try_from(index).map_err(|_| AnalysisError::Invariant)?;
        let id = SymbolId::new(value);
        let module = *module_ids
            .get(&draft.module_path)
            .ok_or(AnalysisError::Invariant)?;
        if draft.kind == SymbolKind::Module
            && let Some(target) = module_ids.get(draft.path.as_str()).copied()
        {
            symbol_modules.insert(id, target);
        }
        local_names
            .entry(module)
            .or_default()
            .insert(draft.name.clone(), id);
        symbols.push(Symbol {
            id,
            module,
            name: draft.name,
            kind: draft.kind,
            path: draft.path,
            span: draft.span,
        });
    }

    Ok(CollectedPackage {
        modules,
        contexts,
        module_ids,
        symbols,
        local_names,
        symbol_modules,
        bindings,
    })
}

/// Diagnoses every module whose parent chain enters a cycle. The source
/// grammar normally makes the graph a tree, but validating the invariant here
/// keeps malformed or future frontend inputs from becoming analyzer state.
fn diagnose_module_cycles(
    modules: &[Module],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    for module in modules {
        let mut seen = BTreeSet::new();
        let mut current = Some(module.id);
        while let Some(id) = current {
            if !seen.insert(id) {
                diagnostics.push(diagnostic(
                    "module-cycle",
                    DiagnosticSeverity::Error,
                    DiagnosticCategory::NameResolution,
                    "a module parent chain contains a cycle",
                    Some(module.span.clone()),
                    Vec::new(),
                    [("canonical_path", safe_qualified_name(&module.path))],
                )?);
                break;
            }
            current = modules
                .get(id.index() as usize)
                .ok_or(AnalysisError::Invariant)?
                .parent;
        }
    }
    Ok(())
}

/// Collects all imports in canonical module and source-span order.
fn collect_imports(
    parsed_sources: &[ParsedSource],
    package: &CollectedPackage,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Vec<ImportDraft>, AnalysisError> {
    let mut imports = Vec::new();
    for context in &package.contexts {
        let source = parsed_sources
            .get(context.source_index)
            .ok_or(AnalysisError::Invariant)?;
        let tree = source.tree();
        let module = *package
            .module_ids
            .get(&context.path)
            .ok_or(AnalysisError::Invariant)?;
        let node = tree.node(context.node).ok_or(AnalysisError::Invariant)?;
        for child in node.children().iter().copied() {
            let child_node = tree.node(child).ok_or(AnalysisError::Invariant)?;
            if !matches!(child_node.form(), SyntaxForm::UseDeclaration) {
                continue;
            }
            let path_node = child_node
                .children()
                .iter()
                .copied()
                .find(|candidate| {
                    tree.node(*candidate)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::Path))
                })
                .ok_or(AnalysisError::Invariant)?;
            let path = parse_path(tree, path_node)?;
            if path.segments.is_empty() {
                diagnostics.push(diagnostic(
                    "unresolved-import",
                    DiagnosticSeverity::Error,
                    DiagnosticCategory::NameResolution,
                    "an import path has no importable final item",
                    Some(path.span.clone()),
                    Vec::new(),
                    [] as [(&str, &str); 0],
                )?);
                continue;
            }
            imports.push(ImportDraft { module, path });
        }
    }
    imports.sort_by(|left, right| {
        left.module
            .cmp(&right.module)
            .then_with(|| left.path.span.cmp(&right.path.span))
    });
    Ok(imports)
}

/// Resolves order-independent imports to one lexical name per target item.
#[allow(clippy::type_complexity)]
fn resolve_imports(
    package: &CollectedPackage,
    imports: &[ImportDraft],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<
    (
        BTreeMap<ModuleId, BTreeMap<Arc<str>, SymbolId>>,
        Vec<BindingRecord>,
        BTreeSet<SourceSpan>,
    ),
    AnalysisError,
> {
    let mut names = BTreeMap::<ModuleId, BTreeMap<Arc<str>, SymbolId>>::new();
    let mut bindings = Vec::new();
    let mut pending = (0..imports.len()).collect::<BTreeSet<_>>();
    let path_spans = imports
        .iter()
        .map(|import| import.path.span.clone())
        .collect();

    loop {
        let mut progressed = false;
        for index in pending.iter().copied().collect::<Vec<_>>() {
            let import = imports.get(index).ok_or(AnalysisError::Invariant)?;
            let Some(target) = resolve_path(package, &names, import.module, &import.path) else {
                continue;
            };
            let imported_name = import
                .path
                .segments
                .last()
                .cloned()
                .ok_or(AnalysisError::Invariant)?;
            let local_collision = package
                .local_names
                .get(&import.module)
                .is_some_and(|locals| locals.contains_key(&imported_name));
            let imported_collision = names
                .get(&import.module)
                .is_some_and(|imports| imports.contains_key(&imported_name));
            if local_collision || imported_collision {
                diagnostics.push(diagnostic(
                    "import-name-collision",
                    DiagnosticSeverity::Error,
                    DiagnosticCategory::NameResolution,
                    "an imported name collides with another visible item",
                    Some(import.path.final_span.clone()),
                    Vec::new(),
                    [("identifier", classify(&imported_name).safe_spelling)],
                )?);
            } else {
                names
                    .entry(import.module)
                    .or_default()
                    .insert(imported_name.clone(), target);
                let module_path = package
                    .modules
                    .get(import.module.index() as usize)
                    .ok_or(AnalysisError::Invariant)?
                    .path
                    .clone();
                bindings.push(BindingRecord {
                    namespace: format!("items:{module_path}"),
                    name: imported_name,
                    span: import.path.final_span.clone(),
                });
            }
            pending.remove(&index);
            progressed = true;
        }
        if !progressed {
            break;
        }
    }

    for index in pending {
        let import = imports.get(index).ok_or(AnalysisError::Invariant)?;
        diagnostics.push(diagnostic(
            "unresolved-import",
            DiagnosticSeverity::Error,
            DiagnosticCategory::NameResolution,
            "an import path does not resolve to one package item",
            Some(import.path.span.clone()),
            Vec::new(),
            [("authored_path", safe_path(&import.path))],
        )?);
    }
    Ok((names, bindings, path_spans))
}

/// Resolves package-item paths while leaving local variable references for the
/// later typed-body pass.
fn resolve_references(
    parsed_sources: &[ParsedSource],
    package: &CollectedPackage,
    imports: &BTreeMap<ModuleId, BTreeMap<Arc<str>, SymbolId>>,
    import_path_spans: &BTreeSet<SourceSpan>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Vec<ResolvedReference>, AnalysisError> {
    let mut references = Vec::new();
    for context in &package.contexts {
        let source = parsed_sources
            .get(context.source_index)
            .ok_or(AnalysisError::Invariant)?;
        let tree = source.tree();
        let module = *package
            .module_ids
            .get(&context.path)
            .ok_or(AnalysisError::Invariant)?;
        let parents = parent_index(tree)?;
        let mut work = tree
            .node(context.node)
            .ok_or(AnalysisError::Invariant)?
            .children()
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>();
        while let Some(node_id) = work.pop() {
            let node = tree.node(node_id).ok_or(AnalysisError::Invariant)?;
            if matches!(node.form(), SyntaxForm::ModuleDeclaration)
                && !is_file_module(tree, node_id)?
            {
                continue;
            }
            if matches!(node.form(), SyntaxForm::Path) {
                if import_path_spans.contains(node.span()) {
                    continue;
                }
                let path = parse_path(tree, node_id)?;
                if let Some(target) = resolve_path(package, imports, module, &path) {
                    let symbol = package
                        .symbols
                        .get(target.index() as usize)
                        .ok_or(AnalysisError::Invariant)?;
                    references.push(ResolvedReference {
                        span: path.span,
                        target,
                        canonical_path: symbol.path.clone(),
                    });
                } else if path_requires_package_item(tree, node_id, &parents, &path)? {
                    diagnostics.push(diagnostic(
                        "unresolved-reference",
                        DiagnosticSeverity::Error,
                        DiagnosticCategory::NameResolution,
                        "a required package-item path does not resolve uniquely",
                        Some(path.span.clone()),
                        Vec::new(),
                        [("authored_path", safe_path(&path))],
                    )?);
                }
                continue;
            }
            for child in node.children().iter().rev().copied() {
                work.push(child);
            }
        }
    }
    references.sort_by(|left, right| {
        left.span
            .cmp(&right.span)
            .then_with(|| left.target.cmp(&right.target))
    });
    references.dedup_by(|left, right| left.span == right.span && left.target == right.target);
    Ok(references)
}

/// Collects idempotent package-wide agent declarations and default-agent
/// validity without placing agents in the ordinary item namespace.
fn collect_agents(
    parsed_sources: &[ParsedSource],
    package: &CollectedPackage,
    diagnostics: &mut Vec<StructuredDiagnostic>,
    bindings: &mut Vec<BindingRecord>,
) -> Result<Vec<AgentName>, AnalysisError> {
    let mut declarations = BTreeMap::<Arc<str>, Vec<SourceSpan>>::new();
    let mut defaults = Vec::<(ModuleId, Arc<str>, SourceSpan)>::new();
    for context in &package.contexts {
        let source = parsed_sources
            .get(context.source_index)
            .ok_or(AnalysisError::Invariant)?;
        let tree = source.tree();
        let module = *package
            .module_ids
            .get(&context.path)
            .ok_or(AnalysisError::Invariant)?;
        let node = tree.node(context.node).ok_or(AnalysisError::Invariant)?;
        for child in node.children().iter().copied() {
            let child_node = tree.node(child).ok_or(AnalysisError::Invariant)?;
            match child_node.form() {
                SyntaxForm::AgentsDeclaration => {
                    for (name, span) in direct_identifiers(tree, child)? {
                        declarations
                            .entry(name.clone())
                            .or_default()
                            .push(span.clone());
                        bindings.push(BindingRecord {
                            namespace: "agents".to_owned(),
                            name,
                            span,
                        });
                    }
                }
                SyntaxForm::DefaultAgentDeclaration => {
                    let (name, span) = declaration_name(tree, child)?;
                    defaults.push((module, name, span));
                }
                _ => {}
            }
        }
    }
    let selections = parsed_sources
        .iter()
        .flat_map(|source| {
            source
                .tree()
                .nodes()
                .iter()
                .map(|node| (source.tree(), node))
        })
        .filter(|(_, node)| {
            matches!(
                node.form(),
                SyntaxForm::WithStatement | SyntaxForm::WithExpression
            )
        })
        .map(|(tree, node)| {
            node.children()
                .iter()
                .filter_map(|child| tree.node(*child))
                .find_map(|child| match child.form() {
                    SyntaxForm::Token(TokenKind::Identifier(name)) => {
                        Some((name.clone(), child.span().clone()))
                    }
                    _ => None,
                })
                .ok_or(AnalysisError::Invariant)
        })
        .collect::<Result<Vec<_>, _>>()?;
    defaults.sort_by(|left, right| left.2.cmp(&right.2));
    if let Some(first) = defaults.first() {
        for duplicate in defaults.iter().skip(1) {
            diagnostics.push(diagnostic(
                "duplicate-default-agent",
                DiagnosticSeverity::Error,
                DiagnosticCategory::NameResolution,
                "the package declares more than one default agent",
                Some(duplicate.2.clone()),
                vec![RelatedSpan {
                    label: Arc::from("first default"),
                    span: first.2.clone(),
                }],
                [] as [(&str, &str); 0],
            )?);
        }
    }
    let root = *package
        .module_ids
        .get("crate")
        .ok_or(AnalysisError::Invariant)?;
    for (module, name, span) in &defaults {
        if *module != root {
            diagnostics.push(diagnostic(
                "default-agent-outside-root",
                DiagnosticSeverity::Error,
                DiagnosticCategory::NameResolution,
                "only the root module may declare the default agent",
                Some(span.clone()),
                Vec::new(),
                [("identifier", classify(name).safe_spelling)],
            )?);
        }
        if !declarations.contains_key(name) {
            diagnostics.push(diagnostic(
                "unresolved-agent",
                DiagnosticSeverity::Error,
                DiagnosticCategory::NameResolution,
                "the selected default agent is not declared package-wide",
                Some(span.clone()),
                Vec::new(),
                [("identifier", classify(name).safe_spelling)],
            )?);
        }
    }
    for (name, span) in selections {
        if !declarations.contains_key(&name) {
            diagnostics.push(diagnostic(
                "unresolved-agent",
                DiagnosticSeverity::Error,
                DiagnosticCategory::NameResolution,
                "a with context does not name a package-wide declared agent",
                Some(span),
                Vec::new(),
                [("identifier", classify(&name).safe_spelling)],
            )?);
        }
    }

    Ok(declarations
        .into_iter()
        .map(|(name, mut declarations)| {
            declarations.sort();
            AgentName { name, declarations }
        })
        .collect())
}

/// Enforces member uniqueness and lexical no-shadowing for parameters, local
/// bindings, loop bindings, pattern bindings, and task handles.
fn collect_member_and_scope_bindings(
    parsed_sources: &[ParsedSource],
    package: &CollectedPackage,
    imports: &BTreeMap<ModuleId, BTreeMap<Arc<str>, SymbolId>>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
    bindings: &mut Vec<BindingRecord>,
) -> Result<(), AnalysisError> {
    for context in &package.contexts {
        let source = parsed_sources
            .get(context.source_index)
            .ok_or(AnalysisError::Invariant)?;
        let tree = source.tree();
        let module = *package
            .module_ids
            .get(&context.path)
            .ok_or(AnalysisError::Invariant)?;
        let mut visible_items = package
            .local_names
            .get(&module)
            .map(|names| names.keys().cloned().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        if let Some(imported) = imports.get(&module) {
            visible_items.extend(imported.keys().cloned());
        }
        let node = tree.node(context.node).ok_or(AnalysisError::Invariant)?;
        for child in node.children().iter().copied() {
            let child_node = tree.node(child).ok_or(AnalysisError::Invariant)?;
            match child_node.form() {
                SyntaxForm::StructDeclaration => {
                    collect_struct_members(tree, child, &context.path, bindings)?
                }
                SyntaxForm::FunctionDeclaration | SyntaxForm::ActionDeclaration => {
                    collect_callable_bindings(
                        tree,
                        child,
                        &context.path,
                        &visible_items,
                        diagnostics,
                        bindings,
                    )?;
                }
                SyntaxForm::ImplDeclaration => {
                    for method in child_node.children().iter().copied() {
                        if tree.node(method).is_some_and(|node| {
                            matches!(node.form(), SyntaxForm::MethodDeclaration)
                        }) {
                            collect_callable_bindings(
                                tree,
                                method,
                                &format!("{}::impl", context.path),
                                &visible_items,
                                diagnostics,
                                bindings,
                            )?;
                        }
                    }
                    collect_impl_members(tree, child, package, imports, module, bindings)?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Collects one struct's fields in their shared receiver-member namespace.
fn collect_struct_members(
    tree: &SyntaxTree,
    declaration: NodeId,
    module_path: &str,
    bindings: &mut Vec<BindingRecord>,
) -> Result<(), AnalysisError> {
    let (struct_name, _) = declaration_name(tree, declaration)?;
    let namespace = format!("members:{module_path}::{struct_name}");
    let node = tree.node(declaration).ok_or(AnalysisError::Invariant)?;
    let members = node
        .children()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::StructField))
        })
        .map(|field| declaration_name(tree, field))
        .collect::<Result<Vec<_>, _>>()?;
    bindings.extend(members.into_iter().map(|(name, span)| BindingRecord {
        namespace: namespace.clone(),
        name,
        span,
    }));
    Ok(())
}

/// Collects method declarations. Cross-checking methods against their resolved
/// receiver fields remains deterministic even when the receiver path is later
/// rejected by type analysis.
fn collect_impl_members(
    tree: &SyntaxTree,
    declaration: NodeId,
    package: &CollectedPackage,
    imports: &BTreeMap<ModuleId, BTreeMap<Arc<str>, SymbolId>>,
    module: ModuleId,
    bindings: &mut Vec<BindingRecord>,
) -> Result<(), AnalysisError> {
    let node = tree.node(declaration).ok_or(AnalysisError::Invariant)?;
    let receiver = node
        .children()
        .iter()
        .copied()
        .find(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Path))
        })
        .map(|path| parse_path(tree, path))
        .transpose()?
        .and_then(|path| {
            resolve_path(package, imports, module, &path).and_then(|target| {
                package
                    .symbols
                    .get(target.index() as usize)
                    .map(|symbol| symbol.path.to_string())
            })
        })
        .unwrap_or_else(|| "unresolved".to_owned());
    let namespace = format!("members:{receiver}");
    let methods = node
        .children()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::MethodDeclaration))
        })
        .map(|method| declaration_name(tree, method))
        .collect::<Result<Vec<_>, _>>()?;
    bindings.extend(methods.into_iter().map(|(name, span)| BindingRecord {
        namespace: namespace.clone(),
        name,
        span,
    }));
    Ok(())
}

/// Checks one callable's lexical declarations with block-scoped explicit-stack
/// traversal.
fn collect_callable_bindings(
    tree: &SyntaxTree,
    callable: NodeId,
    namespace_prefix: &str,
    visible_items: &BTreeSet<Arc<str>>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
    bindings: &mut Vec<BindingRecord>,
) -> Result<(), AnalysisError> {
    let (callable_name, callable_span) = declaration_name(tree, callable)?;
    let namespace = format!(
        "locals:{namespace_prefix}::{callable_name}:{}",
        callable_span.bytes().start()
    );
    let node = tree.node(callable).ok_or(AnalysisError::Invariant)?;
    let parameters = node
        .children()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Parameter))
        })
        .filter_map(|parameter| declaration_name(tree, parameter).ok())
        .collect::<Vec<_>>();
    let mut visible = BTreeMap::<Arc<str>, SourceSpan>::new();
    for (name, span) in parameters {
        check_shadowing(&name, &span, visible_items, &visible, diagnostics)?;
        visible.entry(name.clone()).or_insert_with(|| span.clone());
        bindings.push(BindingRecord {
            namespace: namespace.clone(),
            name,
            span,
        });
    }

    let Some(block) = node.children().iter().copied().find(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::Block))
    }) else {
        return Ok(());
    };
    let parents = parent_index(tree)?;
    let mut work = vec![ScopeEvent::Enter(block, visible)];
    while let Some(event) = work.pop() {
        match event {
            ScopeEvent::Enter(node_id, environment) => {
                let scope_node = tree.node(node_id).ok_or(AnalysisError::Invariant)?;
                let mut current = environment;
                for child in scope_node.children().iter().copied() {
                    check_statement_references(
                        tree,
                        child,
                        &parents,
                        &current,
                        visible_items,
                        diagnostics,
                    )?;
                    schedule_nested_scopes(
                        tree,
                        child,
                        &parents,
                        &current,
                        visible_items,
                        &namespace,
                        diagnostics,
                        bindings,
                        &mut work,
                    )?;
                    let declarations = statement_bindings(tree, child)?;
                    admit_bindings(
                        declarations,
                        visible_items,
                        &mut current,
                        &namespace,
                        diagnostics,
                        bindings,
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// Resolves unqualified value and callable references against declarations
/// visible before one statement. Nested blocks are checked later with their
/// own inherited environments.
fn check_statement_references(
    tree: &SyntaxTree,
    statement: NodeId,
    parents: &[Option<NodeId>],
    visible: &BTreeMap<Arc<str>, SourceSpan>,
    visible_items: &BTreeSet<Arc<str>>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let mut work = vec![statement];
    while let Some(node_id) = work.pop() {
        let node = tree.node(node_id).ok_or(AnalysisError::Invariant)?;
        if node_id != statement && matches!(node.form(), SyntaxForm::Block | SyntaxForm::MatchArm) {
            continue;
        }
        if matches!(node.form(), SyntaxForm::Path) {
            let path = parse_path(tree, node_id)?;
            if path.root == PathRoot::Relative
                && path.segments.len() == 1
                && !path_requires_package_item(tree, node_id, parents, &path)?
            {
                let name = path.segments.first().ok_or(AnalysisError::Invariant)?;
                check_visible_reference(name, path.span, visible, visible_items, diagnostics)?;
            }
            continue;
        }
        for (name, span) in direct_value_references(tree, node_id)? {
            check_visible_reference(&name, span, visible, visible_items, diagnostics)?;
        }
        for child in node.children().iter().rev().copied() {
            work.push(child);
        }
    }
    Ok(())
}

/// Returns direct identifier references that are not represented by a
/// [`SyntaxForm::Path`] node.
fn direct_value_references(
    tree: &SyntaxTree,
    node_id: NodeId,
) -> Result<Vec<(Arc<str>, SourceSpan)>, AnalysisError> {
    let node = tree.node(node_id).ok_or(AnalysisError::Invariant)?;
    match node.form() {
        SyntaxForm::AssignmentStatement => {
            let starts_with_self = node.children().iter().copied().any(|child| {
                tree.node(child).is_some_and(|node| {
                    matches!(
                        node.form(),
                        SyntaxForm::Token(TokenKind::ReservedWord(word))
                            if word.spelling() == "self"
                    )
                })
            });
            if starts_with_self {
                Ok(Vec::new())
            } else {
                Ok(direct_identifiers(tree, node_id)?
                    .into_iter()
                    .take(1)
                    .collect())
            }
        }
        SyntaxForm::DetachStatement | SyntaxForm::JoinExpression => {
            direct_identifiers(tree, node_id)
        }
        SyntaxForm::NamedInput | SyntaxForm::FieldInitializer => {
            let has_explicit_value = node.children().iter().copied().any(|child| {
                tree.node(child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
            });
            if has_explicit_value {
                Ok(Vec::new())
            } else {
                Ok(direct_identifiers(tree, node_id)?
                    .into_iter()
                    .take(1)
                    .collect())
            }
        }
        _ => Ok(Vec::new()),
    }
}

/// Diagnoses one unqualified value reference absent from both the lexical and
/// visible package-item namespaces.
fn check_visible_reference(
    name: &Arc<str>,
    span: SourceSpan,
    visible: &BTreeMap<Arc<str>, SourceSpan>,
    visible_items: &BTreeSet<Arc<str>>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    if !visible.contains_key(name) && !visible_items.contains(name) {
        diagnostics.push(diagnostic(
            "unresolved-reference",
            DiagnosticSeverity::Error,
            DiagnosticCategory::NameResolution,
            "an unqualified name is not declared before use",
            Some(span),
            Vec::new(),
            [("identifier", classify(name).safe_spelling)],
        )?);
    }
    Ok(())
}

/// Explicit traversal event for lexical block analysis.
enum ScopeEvent {
    Enter(NodeId, BTreeMap<Arc<str>, SourceSpan>),
}

/// Returns declarations introduced by one statement into its containing block.
fn statement_bindings(
    tree: &SyntaxTree,
    statement: NodeId,
) -> Result<Vec<(Arc<str>, SourceSpan)>, AnalysisError> {
    let node = tree.node(statement).ok_or(AnalysisError::Invariant)?;
    match node.form() {
        SyntaxForm::LetStatement => {
            let mut declarations = direct_identifiers(tree, statement)?
                .into_iter()
                .take(1)
                .collect::<Vec<_>>();
            for pattern in node.children().iter().copied().filter(|child| {
                tree.node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Pattern))
            }) {
                declarations.extend(pattern_bindings(tree, pattern)?);
            }
            Ok(declarations)
        }
        SyntaxForm::SpawnStatement => Ok(direct_identifiers(tree, statement)?
            .into_iter()
            .take(1)
            .collect()),
        _ => Ok(Vec::new()),
    }
}

/// Schedules every nested lexical block with declarations introduced by its
/// owning `for`, `if let`, or match-arm construct.
#[allow(clippy::too_many_arguments)]
fn schedule_nested_scopes(
    tree: &SyntaxTree,
    root: NodeId,
    parents: &[Option<NodeId>],
    environment: &BTreeMap<Arc<str>, SourceSpan>,
    visible_items: &BTreeSet<Arc<str>>,
    namespace: &str,
    diagnostics: &mut Vec<StructuredDiagnostic>,
    bindings: &mut Vec<BindingRecord>,
    work: &mut Vec<ScopeEvent>,
) -> Result<(), AnalysisError> {
    let mut scan = vec![root];
    while let Some(node_id) = scan.pop() {
        let node = tree.node(node_id).ok_or(AnalysisError::Invariant)?;
        if matches!(node.form(), SyntaxForm::MatchArm) {
            let mut scoped = environment.clone();
            let declarations = node
                .children()
                .iter()
                .copied()
                .find(|child| {
                    tree.node(*child)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::Pattern))
                })
                .map(|pattern| pattern_bindings(tree, pattern))
                .transpose()?
                .unwrap_or_default();
            admit_bindings(
                declarations,
                visible_items,
                &mut scoped,
                namespace,
                diagnostics,
                bindings,
            )?;
            for child in node.children().iter().copied() {
                let child_node = tree.node(child).ok_or(AnalysisError::Invariant)?;
                match child_node.form() {
                    SyntaxForm::Pattern => {}
                    SyntaxForm::Block => work.push(ScopeEvent::Enter(child, scoped.clone())),
                    _ => check_statement_references(
                        tree,
                        child,
                        parents,
                        &scoped,
                        visible_items,
                        diagnostics,
                    )?,
                }
            }
            continue;
        }
        for child in node.children().iter().rev().copied() {
            let child_node = tree.node(child).ok_or(AnalysisError::Invariant)?;
            if matches!(child_node.form(), SyntaxForm::Block) {
                let mut scoped = environment.clone();
                let declarations = scope_bindings(tree, child, parents)?;
                admit_bindings(
                    declarations,
                    visible_items,
                    &mut scoped,
                    namespace,
                    diagnostics,
                    bindings,
                )?;
                work.push(ScopeEvent::Enter(child, scoped));
            } else {
                scan.push(child);
            }
        }
    }
    Ok(())
}

/// Returns declarations whose scope begins at one block boundary.
fn scope_bindings(
    tree: &SyntaxTree,
    block: NodeId,
    parents: &[Option<NodeId>],
) -> Result<Vec<(Arc<str>, SourceSpan)>, AnalysisError> {
    let parent = parents
        .get(block.index())
        .copied()
        .flatten()
        .ok_or(AnalysisError::Invariant)?;
    let node = tree.node(parent).ok_or(AnalysisError::Invariant)?;
    match node.form() {
        SyntaxForm::ForStatement => Ok(direct_identifiers(tree, parent)?
            .into_iter()
            .take(1)
            .collect()),
        SyntaxForm::MatchArm => node
            .children()
            .iter()
            .copied()
            .find(|child| {
                tree.node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Pattern))
            })
            .map(|pattern| pattern_bindings(tree, pattern))
            .transpose()
            .map(Option::unwrap_or_default),
        SyntaxForm::IfStatement => {
            let mut pending = Vec::new();
            for child in node.children().iter().copied() {
                let child_node = tree.node(child).ok_or(AnalysisError::Invariant)?;
                if matches!(child_node.form(), SyntaxForm::Pattern) {
                    pending = pattern_bindings(tree, child)?;
                } else if matches!(child_node.form(), SyntaxForm::Block) {
                    if child == block {
                        return Ok(pending);
                    }
                    pending.clear();
                }
            }
            Ok(Vec::new())
        }
        _ => Ok(Vec::new()),
    }
}

/// Extracts binding identifiers from one pattern without mistaking enum or
/// operation-error path segments for bindings.
fn pattern_bindings(
    tree: &SyntaxTree,
    pattern: NodeId,
) -> Result<Vec<(Arc<str>, SourceSpan)>, AnalysisError> {
    let mut bindings = Vec::new();
    let mut work = vec![pattern];
    while let Some(node_id) = work.pop() {
        let node = tree.node(node_id).ok_or(AnalysisError::Invariant)?;
        let direct = direct_identifiers(tree, node_id)?;
        let is_path = node.children().iter().copied().any(|child| {
            tree.node(child).is_some_and(|node| {
                matches!(
                    node.form(),
                    SyntaxForm::Token(TokenKind::Punctuation(Punctuation::PathSeparator))
                )
            })
        });
        if direct.len() == 1 && !is_path {
            bindings.extend(direct);
        }
        for child in node.children().iter().rev().copied() {
            if tree
                .node(child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Pattern))
            {
                work.push(child);
            }
        }
    }
    Ok(bindings)
}

/// Checks and records declarations in authored order so duplicates within one
/// pattern are diagnosed against the first binding.
fn admit_bindings(
    declarations: Vec<(Arc<str>, SourceSpan)>,
    visible_items: &BTreeSet<Arc<str>>,
    visible: &mut BTreeMap<Arc<str>, SourceSpan>,
    namespace: &str,
    diagnostics: &mut Vec<StructuredDiagnostic>,
    bindings: &mut Vec<BindingRecord>,
) -> Result<(), AnalysisError> {
    for (name, span) in declarations {
        check_shadowing(&name, &span, visible_items, visible, diagnostics)?;
        visible.entry(name.clone()).or_insert_with(|| span.clone());
        bindings.push(BindingRecord {
            namespace: namespace.to_owned(),
            name,
            span,
        });
    }
    Ok(())
}

/// Diagnoses one declaration that collides with a visible item or lexical name.
fn check_shadowing(
    name: &Arc<str>,
    span: &SourceSpan,
    visible_items: &BTreeSet<Arc<str>>,
    visible: &BTreeMap<Arc<str>, SourceSpan>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let related = visible.get(name).map_or_else(Vec::new, |previous| {
        vec![RelatedSpan {
            label: Arc::from("visible declaration"),
            span: previous.clone(),
        }]
    });
    if visible_items.contains(name) || visible.contains_key(name) {
        diagnostics.push(diagnostic(
            "shadowed-name",
            DiagnosticSeverity::Error,
            DiagnosticCategory::NameResolution,
            "a lexical declaration duplicates or shadows a visible name",
            Some(span.clone()),
            related,
            [("identifier", classify(name).safe_spelling)],
        )?);
    }
    Ok(())
}

/// Checks every exact identifier occurrence for NFC, excluded scalars, and
/// Recommended single-script usage.
fn check_all_identifier_security(
    parsed_sources: &[ParsedSource],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    for source in parsed_sources {
        for node in source.tree().nodes() {
            let SyntaxForm::Token(TokenKind::Identifier(value)) = node.form() else {
                continue;
            };
            let security = classify(value);
            if !security.nfc {
                diagnostics.push(identifier_diagnostic(
                    "identifier-not-nfc",
                    DiagnosticSeverity::Error,
                    "an identifier is not already Unicode 16 NFC",
                    node.span(),
                    value,
                    &security,
                )?);
            }
            if security.excluded {
                diagnostics.push(identifier_diagnostic(
                    "identifier-security",
                    DiagnosticSeverity::Error,
                    "an identifier contains a security-excluded Unicode scalar",
                    node.span(),
                    value,
                    &security,
                )?);
            }
            if !security.recommended_single_script {
                diagnostics.push(identifier_diagnostic(
                    "identifier-script-warning",
                    DiagnosticSeverity::Warning,
                    "an identifier is outside one Recommended single-script set",
                    node.span(),
                    value,
                    &security,
                )?);
            }
        }
    }
    Ok(())
}

/// Emits exact UTS #39 skeleton collisions both within and across lookup
/// namespaces without treating the warning as package invalidity.
fn check_confusable_bindings(
    bindings: &[BindingRecord],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let mut by_skeleton = BTreeMap::<String, Vec<&BindingRecord>>::new();
    for binding in bindings {
        by_skeleton
            .entry(classify(&binding.name).skeleton)
            .or_default()
            .push(binding);
    }
    for (skeleton, mut group) in by_skeleton {
        group.sort();
        let distinct = group
            .iter()
            .map(|binding| binding.name.as_ref())
            .collect::<BTreeSet<_>>();
        if distinct.len() < 2 {
            continue;
        }
        let first = group[0];
        for collision in group.into_iter().skip(1) {
            if collision.name == first.name {
                continue;
            }
            let relation = if collision.namespace == first.namespace {
                "same-namespace"
            } else {
                "cross-namespace"
            };
            diagnostics.push(diagnostic(
                "identifier-confusable-collision",
                DiagnosticSeverity::Warning,
                DiagnosticCategory::IdentifierSecurity,
                "distinct identifier spellings have the same Unicode 16 confusable skeleton",
                Some(collision.span.clone()),
                vec![RelatedSpan {
                    label: Arc::from("confusable identifier"),
                    span: first.span.clone(),
                }],
                [
                    ("identifier", classify(&collision.name).safe_spelling),
                    ("namespace_relation", relation.to_owned()),
                    ("skeleton", skeleton.clone()),
                ],
            )?);
        }
    }
    Ok(())
}

/// Resolves one path through module-local item and import namespaces.
fn resolve_path(
    package: &CollectedPackage,
    imports: &BTreeMap<ModuleId, BTreeMap<Arc<str>, SymbolId>>,
    current: ModuleId,
    path: &PathSpec,
) -> Option<SymbolId> {
    let root = *package.module_ids.get("crate")?;
    let mut module = match path.root {
        PathRoot::Relative | PathRoot::SelfModule => current,
        PathRoot::Crate => root,
        PathRoot::Super(count) => {
            let mut value = current;
            for _ in 0..count {
                value = package.modules.get(value.index() as usize)?.parent?;
            }
            value
        }
    };
    let mut target = None;
    for (index, segment) in path.segments.iter().enumerate() {
        let local = package
            .local_names
            .get(&module)
            .and_then(|names| names.get(segment));
        let imported = imports.get(&module).and_then(|names| names.get(segment));
        let found = local.or(imported).copied()?;
        target = Some(found);
        if index + 1 != path.segments.len() {
            if let Some(target_module) = package.symbol_modules.get(&found).copied() {
                module = target_module;
            } else if package
                .symbols
                .get(found.index() as usize)
                .is_some_and(|symbol| symbol.kind == SymbolKind::Enum)
                && index + 2 == path.segments.len()
            {
                return Some(found);
            } else {
                return None;
            }
        }
    }
    target
}

/// Determines whether an unresolved path is unambiguously package-owned at
/// this stage rather than a possible local value reference.
fn path_requires_package_item(
    tree: &SyntaxTree,
    node: NodeId,
    parents: &[Option<NodeId>],
    path: &PathSpec,
) -> Result<bool, AnalysisError> {
    if path.root != PathRoot::Relative || path.segments.len() > 1 {
        return Ok(true);
    }
    let mut current = parents.get(node.index()).copied().flatten();
    while let Some(parent) = current {
        let form = tree.node(parent).ok_or(AnalysisError::Invariant)?.form();
        if matches!(
            form,
            SyntaxForm::UseDeclaration
                | SyntaxForm::ImplDeclaration
                | SyntaxForm::ValueType
                | SyntaxForm::StructExpression
        ) {
            return Ok(true);
        }
        if matches!(form, SyntaxForm::Expression | SyntaxForm::Block) {
            break;
        }
        current = parents.get(parent.index()).copied().flatten();
    }
    Ok(false)
}

/// Parses the direct token children of one frontend path node.
fn parse_path(tree: &SyntaxTree, path: NodeId) -> Result<PathSpec, AnalysisError> {
    let node = tree.node(path).ok_or(AnalysisError::Invariant)?;
    if !matches!(node.form(), SyntaxForm::Path) {
        return Err(AnalysisError::Invariant);
    }
    let mut root = PathRoot::Relative;
    let mut segments = Vec::new();
    let mut spans = Vec::new();
    let mut leading_super = 0_u32;
    for child in node.children().iter().copied() {
        let child_node = tree.node(child).ok_or(AnalysisError::Invariant)?;
        match child_node.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => {
                segments.push(value.clone());
                spans.push(child_node.span().clone());
            }
            SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "crate" => {
                root = PathRoot::Crate;
            }
            SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self" => {
                root = PathRoot::SelfModule;
            }
            SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "super" => {
                leading_super = leading_super
                    .checked_add(1)
                    .ok_or(AnalysisError::Invariant)?;
                root = PathRoot::Super(leading_super);
            }
            _ => {}
        }
    }
    let final_span = spans.last().cloned().ok_or(AnalysisError::Invariant)?;
    Ok(PathSpec {
        root,
        segments,
        span: node.span().clone(),
        final_span,
    })
}

/// Creates a parent lookup for one arena-backed syntax tree.
fn parent_index(tree: &SyntaxTree) -> Result<Vec<Option<NodeId>>, AnalysisError> {
    let mut parents = vec![None; tree.nodes().len()];
    for (index, node) in tree.nodes().iter().enumerate() {
        let parent = NodeId::from_index(index);
        for child in node.children().iter().copied() {
            let slot = parents
                .get_mut(child.index())
                .ok_or(AnalysisError::Invariant)?;
            *slot = Some(parent);
        }
    }
    Ok(parents)
}

/// Maps one package source path to its canonical module path.
fn module_path_from_source(path: &str) -> Result<String, AnalysisError> {
    if path == "main.gnt" {
        return Ok("crate".to_owned());
    }
    let stem = path
        .strip_suffix("/mod.gnt")
        .or_else(|| path.strip_suffix(".gnt"))
        .ok_or(AnalysisError::Invariant)?;
    if stem.is_empty() {
        return Err(AnalysisError::Invariant);
    }
    Ok(format!("crate::{}", stem.replace('/', "::")))
}

/// Returns the parent of a canonical module path.
fn parent_module_path(path: &str) -> Option<String> {
    path.rsplit_once("::").map(|(parent, _)| parent.to_owned())
}

/// Joins one exact identifier onto a canonical module path.
fn join_module_path(parent: &str, name: &str) -> String {
    format!("{parent}::{name}")
}

/// Maps declaration syntax forms to package symbol kinds.
fn item_kind(form: &SyntaxForm) -> Option<SymbolKind> {
    Some(match form {
        SyntaxForm::ModuleDeclaration => SymbolKind::Module,
        SyntaxForm::StructDeclaration => SymbolKind::Struct,
        SyntaxForm::EnumDeclaration => SymbolKind::Enum,
        SyntaxForm::FunctionDeclaration => SymbolKind::Function,
        SyntaxForm::ActionDeclaration => SymbolKind::Action,
        _ => return None,
    })
}

/// Returns the first direct identifier retained by one declaration node.
fn declaration_name(
    tree: &SyntaxTree,
    declaration: NodeId,
) -> Result<(Arc<str>, SourceSpan), AnalysisError> {
    direct_identifiers(tree, declaration)?
        .into_iter()
        .next()
        .ok_or(AnalysisError::Invariant)
}

/// Returns direct identifier token children in authored order.
fn direct_identifiers(
    tree: &SyntaxTree,
    node: NodeId,
) -> Result<Vec<(Arc<str>, SourceSpan)>, AnalysisError> {
    let node = tree.node(node).ok_or(AnalysisError::Invariant)?;
    Ok(node
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .filter_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => {
                Some((value.clone(), child.span().clone()))
            }
            _ => None,
        })
        .collect())
}

/// Returns whether a module declaration uses the semicolon file form.
fn is_file_module(tree: &SyntaxTree, declaration: NodeId) -> Result<bool, AnalysisError> {
    let node = tree.node(declaration).ok_or(AnalysisError::Invariant)?;
    Ok(node.children().iter().copied().any(|child| {
        tree.node(child).is_some_and(|node| {
            matches!(
                node.form(),
                SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Semicolon))
            )
        })
    }))
}

/// Checks the shared field-and-method namespace for every resolved receiver.
fn check_member_collisions(
    bindings: &[BindingRecord],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let mut first = BTreeMap::<(&str, &str), &SourceSpan>::new();
    for binding in bindings
        .iter()
        .filter(|binding| binding.namespace.starts_with("members:"))
    {
        let key = (binding.namespace.as_str(), binding.name.as_ref());
        if let Some(previous) = first.get(&key) {
            diagnostics.push(diagnostic(
                "duplicate-member",
                DiagnosticSeverity::Error,
                DiagnosticCategory::NameResolution,
                "a field or inherent method name is duplicated for one receiver",
                Some(binding.span.clone()),
                vec![RelatedSpan {
                    label: Arc::from("first declaration"),
                    span: (*previous).clone(),
                }],
                [
                    ("identifier", classify(&binding.name).safe_spelling),
                    ("namespace", safe_qualified_name(&binding.namespace)),
                ],
            )?);
        } else {
            first.insert(key, &binding.span);
        }
    }
    Ok(())
}

/// Builds one disclosure-neutral identifier diagnostic.
fn identifier_diagnostic(
    code: &str,
    severity: DiagnosticSeverity,
    message: &str,
    span: &SourceSpan,
    value: &str,
    security: &IdentifierSecurity,
) -> Result<StructuredDiagnostic, AnalysisError> {
    diagnostic(
        code,
        severity,
        DiagnosticCategory::IdentifierSecurity,
        message,
        Some(span.clone()),
        Vec::new(),
        [
            ("identifier", security.safe_spelling.clone()),
            ("scripts", security.scripts.join(",")),
            ("skeleton", security.skeleton.clone()),
            ("utf8_length", value.len().to_string()),
        ],
    )
}

/// Constructs a structured analysis diagnostic from already safe fields.
fn diagnostic<K, V, const N: usize>(
    code: &str,
    severity: DiagnosticSeverity,
    category: DiagnosticCategory,
    message: &str,
    primary: Option<SourceSpan>,
    related: Vec<RelatedSpan>,
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
    let code = DiagnosticCode::new(code).map_err(|_| AnalysisError::Invariant)?;
    StructuredDiagnostic::new(
        DiagnosticMetadata {
            phase: DiagnosticPhase::Analysis,
            severity,
            category,
            code,
        },
        message,
        primary,
        related,
        fields,
    )
    .map_err(|_| AnalysisError::Invariant)
}

/// Renders a source path into a safe machine field without retaining aliases
/// in canonical output.
fn safe_path(path: &PathSpec) -> String {
    let prefix = match path.root {
        PathRoot::Relative => String::new(),
        PathRoot::Crate => "crate::".to_owned(),
        PathRoot::SelfModule => "self::".to_owned(),
        PathRoot::Super(count) => "super::".repeat(count as usize),
    };
    format!(
        "{prefix}{}",
        path.segments
            .iter()
            .map(|segment| classify(segment).safe_spelling)
            .collect::<Vec<_>>()
            .join("::")
    )
}

/// Escapes every identifier-like component in an internal qualified name.
fn safe_qualified_name(value: &str) -> String {
    value
        .split("::")
        .map(|component| {
            if component.is_empty() || component == "crate" || component.starts_with("locals:") {
                component.to_owned()
            } else {
                classify(component).safe_spelling
            }
        })
        .collect::<Vec<_>>()
        .join("::")
}

/// Escapes each package-path component while preserving slash structure.
fn safe_package_path(value: &str) -> String {
    value
        .split('/')
        .map(|component| {
            let (stem, suffix) = component
                .strip_suffix(".gnt")
                .map_or((component, ""), |stem| (stem, ".gnt"));
            format!("{}{suffix}", classify(stem).safe_spelling)
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Sorts, bounds, and returns the completed structural judgment.
fn finish_structure(
    package: CollectedPackage,
    references: Vec<ResolvedReference>,
    agents: Vec<AgentName>,
    mut diagnostics: Vec<StructuredDiagnostic>,
    mut counters: SourceCounters,
) -> Result<PackageStructure, AnalysisError> {
    diagnostics.sort();
    diagnostics.dedup();
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
    Ok(PackageStructure {
        status,
        modules: package.modules,
        symbols: package.symbols,
        references,
        agents,
        diagnostics: retained,
        counters,
    })
}

/// Returns half-open runs whose selected string keys compare equal.
fn equal_runs<T>(values: &[T], key: impl Fn(&T) -> &str) -> Vec<std::ops::Range<usize>> {
    let mut runs = Vec::new();
    let mut start = 0;
    while start < values.len() {
        let mut end = start + 1;
        while end < values.len() && key(&values[start]) == key(&values[end]) {
            end += 1;
        }
        runs.push(start..end);
        start = end;
    }
    runs
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use gantry_core::source::SourceLimits;
    use gantry_frontend::validate_package_syntax;

    use super::analyze_package_structure;
    use crate::{AnalysisError, AnalysisStatus};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "gantry-package-analysis-{}-{suffix}",
                std::process::id()
            ));
            assert!(fs::create_dir(&path).is_ok());
            Self(path)
        }

        fn write(&self, path: &str, source: &str) {
            let path = self.0.join(path);
            if let Some(parent) = path.parent() {
                assert!(fs::create_dir_all(parent).is_ok());
            }
            assert!(fs::write(path, source).is_ok());
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn limits(diagnostics: u64) -> SourceLimits {
        SourceLimits::new(16, 16_384, 65_536, 16_384, diagnostics)
            .unwrap_or_else(|_| unreachable!("positive limits"))
    }

    #[test]
    fn module_symbols_and_imports_are_canonical_and_order_independent() {
        fn analyze(root_items: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
            let root = TempDirectory::new();
            root.write(
                "main.gnt",
                &format!(
                    "{root_items}\nuse a::Thing;\nfn main(value: Thing) -> Thing {{ z::make(value) }}"
                ),
            );
            root.write("a.gnt", "struct Thing {}");
            root.write(
                "z.gnt",
                "use crate::a::Thing; fn make(value: Thing) -> Thing { value }",
            );
            let phase = validate_package_syntax(&root.0, limits(32));
            assert!(phase.is_ok());
            let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
            let analysis = analyze_package_structure(&phase);
            assert!(analysis.is_ok(), "{analysis:?}");
            let analysis = analysis.unwrap_or_else(|_| unreachable!("checked above"));
            assert_eq!(analysis.status(), AnalysisStatus::Valid);
            (
                analysis
                    .modules()
                    .iter()
                    .map(|module| module.path.to_string())
                    .collect(),
                analysis
                    .symbols()
                    .iter()
                    .map(|symbol| symbol.path.to_string())
                    .collect(),
                analysis
                    .references()
                    .iter()
                    .map(|reference| reference.canonical_path.to_string())
                    .collect(),
            )
        }

        let first = analyze("mod z; mod a;");
        let second = analyze("mod a; mod z;");
        assert_eq!(first, second);
        assert_eq!(first.0, ["crate", "crate::a", "crate::z"]);
        assert!(first.1.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(first.2.contains(&"crate::a::Thing".to_owned()));
        assert!(first.2.contains(&"crate::z::make".to_owned()));
    }

    #[test]
    fn missing_and_ambiguous_file_modules_are_analysis_errors() {
        let missing = TempDirectory::new();
        missing.write("main.gnt", "mod absent; fn main() {}");
        let phase = validate_package_syntax(&missing.0, limits(32));
        assert!(phase.is_ok(), "{phase:?}");
        let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(phase.module_resolution_issues().len(), 1);
        let analysis = analyze_package_structure(&phase);
        assert!(analysis.is_ok(), "{analysis:?}");
        let analysis = analysis.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(analysis.status(), AnalysisStatus::Invalid);
        assert!(analysis.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_str() == "missing-module-source"
                && diagnostic
                    .fields
                    .get("canonical_path")
                    .is_some_and(|value| value.as_ref() == "crate::absent")
        }));

        let ambiguous = TempDirectory::new();
        ambiguous.write("main.gnt", "mod child; fn main() {}");
        ambiguous.write("child.gnt", "fn flat() {}");
        ambiguous.write("child/mod.gnt", "fn nested() {}");
        let phase = validate_package_syntax(&ambiguous.0, limits(32));
        assert!(phase.is_ok(), "{phase:?}");
        let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(phase.module_resolution_issues().len(), 1);
        let analysis = analyze_package_structure(&phase);
        assert!(analysis.is_ok(), "{analysis:?}");
        let analysis = analysis.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(analysis.status(), AnalysisStatus::Invalid);
        assert!(analysis.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_str() == "ambiguous-module-resolution"
                && diagnostic
                    .fields
                    .get("flat_candidate")
                    .is_some_and(|value| value.as_ref() == "child.gnt")
                && diagnostic
                    .fields
                    .get("nested_candidate")
                    .is_some_and(|value| value.as_ref() == "child/mod.gnt")
        }));
    }

    #[test]
    fn malformed_module_parent_cycles_are_diagnosed_without_recursion() {
        let root = TempDirectory::new();
        root.write("main.gnt", "fn main() {}");
        let phase = validate_package_syntax(&root.0, limits(32));
        assert!(phase.is_ok(), "{phase:?}");
        let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
        let span = phase.parsed_sources()[0].tree().nodes()[0].span().clone();
        let modules = vec![
            crate::Module {
                id: crate::ModuleId::new(0),
                path: Arc::from("crate"),
                parent: Some(crate::ModuleId::new(1)),
                span: span.clone(),
            },
            crate::Module {
                id: crate::ModuleId::new(1),
                path: Arc::from("crate::child"),
                parent: Some(crate::ModuleId::new(0)),
                span,
            },
        ];
        let mut diagnostics = Vec::new();
        assert!(super::diagnose_module_cycles(&modules, &mut diagnostics).is_ok());
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code.as_str() == "module-cycle")
                .count(),
            2
        );
    }

    #[test]
    fn member_names_and_visible_items_cannot_be_shadowed() {
        let root = TempDirectory::new();
        root.write(
            "main.gnt",
            "struct Report { revise: String }\nimpl Report { fn revise(self) {} }\nfn main(Report: String) {}",
        );
        let phase = validate_package_syntax(&root.0, limits(32));
        assert!(phase.is_ok());
        let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
        let analysis = analyze_package_structure(&phase);
        assert!(analysis.is_ok(), "{analysis:?}");
        let analysis = analysis.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(analysis.status(), AnalysisStatus::Invalid);
        let codes = analysis
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"duplicate-member"));
        assert!(codes.contains(&"shadowed-name"));
    }

    #[test]
    fn agent_selection_uses_only_the_separate_package_namespace() {
        let root = TempDirectory::new();
        root.write(
            "main.gnt",
            r#"
agents { researcher }
default agent = researcher;
struct researcher {}
fn main() {
    with researcher {}
    with missing {}
}
"#,
        );
        let phase = validate_package_syntax(&root.0, limits(32));
        assert!(phase.is_ok(), "{phase:?}");
        let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
        let analysis = analyze_package_structure(&phase);
        assert!(analysis.is_ok(), "{analysis:?}");
        let analysis = analysis.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(analysis.status(), AnalysisStatus::Invalid);
        assert_eq!(analysis.agents().len(), 1);
        assert_eq!(analysis.agents()[0].name.as_ref(), "researcher");
        assert_eq!(
            analysis
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code.as_str() == "unresolved-agent")
                .count(),
            1
        );
    }

    #[test]
    fn lexical_references_must_resolve_after_declaration() {
        let root = TempDirectory::new();
        root.write(
            "main.gnt",
            r#"
fn consume(value: Int) {}
fn main() {
    consume(value);
    let value: Int = 1;
    consume(value);
    consume(missing);
}
"#,
        );
        let phase = validate_package_syntax(&root.0, limits(32));
        assert!(phase.is_ok(), "{phase:?}");
        let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
        let analysis = analyze_package_structure(&phase);
        assert!(analysis.is_ok(), "{analysis:?}");
        let analysis = analysis.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(analysis.status(), AnalysisStatus::Invalid);
        assert_eq!(
            analysis
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code.as_str() == "unresolved-reference")
                .count(),
            2
        );
    }

    #[test]
    fn pattern_and_loop_bindings_obey_lexical_no_shadowing() {
        let root = TempDirectory::new();
        root.write(
            "main.gnt",
            r#"
fn main(value: Option<Int>, values: List<Int>) {
    let (left, left): Tuple<Int, Int> = (1, 2);
    if let Some(item) = value {
        let item: Int = 1;
    }
    match value {
        Some(member) => {
            let member: Int = 1;
        },
        None => {},
    }
    for value in values {
        let value: Int = 1;
    }
}
"#,
        );
        let phase = validate_package_syntax(&root.0, limits(32));
        assert!(phase.is_ok(), "{phase:?}");
        let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
        let analysis = analyze_package_structure(&phase);
        assert!(analysis.is_ok(), "{analysis:?}");
        let analysis = analysis.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(analysis.status(), AnalysisStatus::Invalid);
        assert_eq!(
            analysis
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code.as_str() == "shadowed-name")
                .count(),
            5
        );
    }

    #[test]
    fn confusable_and_mixed_script_identifiers_warn_without_invalidating() {
        let root = TempDirectory::new();
        root.write("main.gnt", "struct paypal {} struct раypal {} fn main() {}");
        let phase = validate_package_syntax(&root.0, limits(32));
        assert!(phase.is_ok());
        let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
        let analysis = analyze_package_structure(&phase);
        assert!(analysis.is_ok(), "{analysis:?}");
        let analysis = analysis.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(analysis.status(), AnalysisStatus::Valid);
        assert!(analysis.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_str() == "identifier-confusable-collision"
                && diagnostic
                    .fields
                    .get("skeleton")
                    .is_some_and(|value| value.as_ref() == "paypal")
        }));
        assert!(
            analysis
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "identifier-script-warning")
        );
    }

    #[test]
    fn analysis_charges_the_shared_diagnostic_limit_incrementally() {
        let root = TempDirectory::new();
        root.write(
            "main.gnt",
            "struct Item {} fn main(Item: String, Item: String) {}",
        );
        let phase = validate_package_syntax(&root.0, limits(1));
        assert!(phase.is_ok());
        let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
        let analysis = analyze_package_structure(&phase);
        assert!(matches!(
            analysis,
            Err(AnalysisError::ResourceLimit { diagnostics, .. }) if diagnostics.len() == 1
        ));
    }
}
