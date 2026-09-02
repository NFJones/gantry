//! Canonical generated schemas and entry-boundary inventories.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::source::{FrontendResourceLimit, SourceSpan};
use gantry_frontend::{NodeId, ParsedSource, Punctuation, SyntaxForm, SyntaxTree, TokenKind};
use gantry_ir::generated::{TemplateKind, TypeKind};
use gantry_ir::{
    ActionInventory, ArtifactEncodingError, ArtifactLimits, CanonicalPath,
    CanonicalTemplateIdentity, ConcreteIdentity, ConcreteInstantiation, ConcreteSourceMapEntry,
    EntryInventory, GeneratedSchemaObject, GenericTemplate, Predicate, SchemaObjectError,
    SourceOriginSet, TypeDescriptor, TypeExpression, WorkflowFacts,
};
use sha2::{Digest, Sha256};

use crate::generics::{ExactTypeSubstitution, TypeParameterKey, collect_where_predicates};
use crate::{
    AnalysisError, DeclaredEnumVariant, DeclaredStructField, DeclaredValueShape,
    DeclaredValueShapes, GenericTypeFact, PackageStructure, Symbol, SymbolKind, TypeBinder,
    TypeFact,
};

const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

#[derive(Clone, Debug)]
struct StructField {
    name: Arc<str>,
    ty: TypeExpression,
    default: Option<String>,
}

#[derive(Clone, Debug)]
struct ConcreteStructField {
    name: Arc<str>,
    ty: TypeDescriptor,
    default: Option<String>,
}

#[derive(Clone, Debug)]
enum DeclaredShape {
    Struct {
        declaration: SourceSpan,
        required: Vec<TypeParameterKey>,
        predicates: Vec<Predicate>,
        fields: Vec<StructField>,
    },
    Enum {
        declaration: SourceSpan,
        required: Vec<TypeParameterKey>,
        predicates: Vec<Predicate>,
        variants: Vec<(Arc<str>, Option<TypeExpression>)>,
    },
}

#[derive(Clone, Debug)]
enum ConcreteDeclaredShape {
    Struct(Vec<ConcreteStructField>),
    Enum(Vec<(Arc<str>, Option<TypeDescriptor>)>),
}

pub(crate) struct SchemaGenericFacts {
    pub(crate) templates: Vec<GenericTemplate>,
    pub(crate) instantiations: Vec<ConcreteInstantiation>,
    pub(crate) source_map: Vec<ConcreteSourceMapEntry>,
    pub(crate) concrete_types: Vec<TypeDescriptor>,
}

pub(crate) enum SchemaAnalysisError {
    ResourceLimit(FrontendResourceLimit),
    Invariant,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn analyze_generated_schemas(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    generic_facts: &[GenericTypeFact],
    binders: &[TypeBinder],
    structure: &PackageStructure,
    workflows: &[WorkflowFacts],
    actions: &[ActionInventory],
    limits: ArtifactLimits,
) -> Result<
    (
        Option<EntryInventory>,
        Option<GeneratedSchemaObject>,
        DeclaredValueShapes,
        SchemaGenericFacts,
    ),
    SchemaAnalysisError,
> {
    let symbols_by_span = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.span.clone(), symbol))
        .collect::<BTreeMap<_, _>>();
    let symbols_by_id = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.id, symbol))
        .collect::<BTreeMap<_, _>>();
    let references = structure
        .references()
        .iter()
        .map(|reference| (reference.span.clone(), reference.target))
        .collect::<BTreeMap<_, _>>();
    let shapes = collect_declared_shapes(
        sources,
        facts,
        generic_facts,
        binders,
        &symbols_by_span,
        &symbols_by_id,
        &references,
    )?;
    let entry = collect_entry(sources, facts, structure)?;
    let mut roots = BTreeMap::<String, (TypeDescriptor, BTreeSet<SourceSpan>)>::new();
    if let Some(entry) = &entry {
        if let Some(parameter) = &entry.parameter {
            insert_schema_root(&mut roots, parameter.clone(), generic_facts, None);
        }
        insert_schema_root(&mut roots, entry.result.clone(), generic_facts, None);
    }
    for operation in workflows.iter().flat_map(|workflow| &workflow.operations) {
        insert_schema_root(
            &mut roots,
            operation.result.clone(),
            generic_facts,
            Some(operation.source.clone()),
        );
    }
    for action in actions {
        for parameter in &action.parameters {
            insert_schema_root(
                &mut roots,
                parameter.ty().clone(),
                generic_facts,
                Some(action.source.clone()),
            );
        }
        insert_schema_root(
            &mut roots,
            action.result.clone(),
            generic_facts,
            Some(action.source.clone()),
        );
    }
    let mut generic = schema_generic_templates(&shapes)?;
    if roots.is_empty() {
        return Ok((entry, None, public_declared_shapes(&shapes)?, generic));
    }

    let mut entries = Vec::with_capacity(roots.len());
    let mut concrete_origins = BTreeMap::<TypeDescriptor, BTreeSet<SourceSpan>>::new();
    for (root, origins) in roots.into_values() {
        let (schema, reachable) = build_root_schema(&root, &shapes)?;
        for descriptor in reachable {
            let Some(shape) = descriptor.declared_path().and_then(|path| shapes.get(path)) else {
                return Err(SchemaAnalysisError::Invariant);
            };
            if shape_required(shape).is_empty() {
                continue;
            }
            let retained = concrete_origins.entry(descriptor.clone()).or_default();
            retained.extend(origins.iter().cloned());
            retained.extend(
                generic_facts
                    .iter()
                    .filter(|fact| fact.descriptor.as_ref() == Some(&descriptor))
                    .map(|fact| fact.span.clone()),
            );
        }
        entries.push((root, Arc::from(schema.into_bytes())));
    }
    extend_schema_generic_facts(&mut generic, concrete_origins, &shapes)?;
    entries.sort_by(|left, right| {
        left.0
            .canonical_string()
            .as_bytes()
            .cmp(right.0.canonical_string().as_bytes())
    });
    let schemas = GeneratedSchemaObject::new(entries, limits).map_err(|error| match error {
        SchemaObjectError::Encoding(ArtifactEncodingError::ResourceLimit(error)) => {
            SchemaAnalysisError::ResourceLimit(error)
        }
        SchemaObjectError::Encoding(ArtifactEncodingError::Empty)
        | SchemaObjectError::InvalidSchemaBytes
        | SchemaObjectError::NoncanonicalOrder => SchemaAnalysisError::Invariant,
    })?;
    Ok((
        entry,
        Some(schemas),
        public_declared_shapes(&shapes)?,
        generic,
    ))
}

fn insert_schema_root(
    roots: &mut BTreeMap<String, (TypeDescriptor, BTreeSet<SourceSpan>)>,
    descriptor: TypeDescriptor,
    generic_facts: &[GenericTypeFact],
    source: Option<SourceSpan>,
) {
    let origins = roots
        .entry(descriptor.canonical_string())
        .or_insert_with(|| (descriptor.clone(), BTreeSet::new()));
    origins.1.extend(
        generic_facts
            .iter()
            .filter(|fact| fact.descriptor.as_ref() == Some(&descriptor))
            .map(|fact| fact.span.clone()),
    );
    origins.1.extend(source);
}

fn shape_required(shape: &DeclaredShape) -> &[TypeParameterKey] {
    match shape {
        DeclaredShape::Struct { required, .. } | DeclaredShape::Enum { required, .. } => required,
    }
}

fn shape_template_identity(
    path: &CanonicalPath,
    shape: &DeclaredShape,
) -> Result<CanonicalTemplateIdentity, SchemaAnalysisError> {
    let arguments = shape_required(shape)
        .iter()
        .map(|parameter| {
            TypeExpression::parameter(parameter.binder_depth, parameter.ordinal, u64::MAX)
                .map_err(|_| SchemaAnalysisError::Invariant)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CanonicalTemplateIdentity::free(path, &arguments))
}

fn schema_generic_templates(
    shapes: &BTreeMap<CanonicalPath, DeclaredShape>,
) -> Result<SchemaGenericFacts, SchemaAnalysisError> {
    let mut templates = Vec::new();
    for (path, shape) in shapes {
        let required = shape_required(shape);
        if required.is_empty() {
            continue;
        }
        let predicates = match shape {
            DeclaredShape::Struct { predicates, .. } | DeclaredShape::Enum { predicates, .. } => {
                predicates
            }
        };
        templates.push(
            GenericTemplate::new(
                TemplateKind::DeclaredType,
                shape_template_identity(path, shape)?,
                u64::try_from(required.len()).map_err(|_| SchemaAnalysisError::Invariant)?,
                predicates.clone(),
                Default::default(),
            )
            .map_err(|_| SchemaAnalysisError::Invariant)?,
        );
    }
    templates.sort_by(|left, right| {
        (left.kind(), left.identity()).cmp(&(right.kind(), right.identity()))
    });
    Ok(SchemaGenericFacts {
        templates,
        instantiations: Vec::new(),
        source_map: Vec::new(),
        concrete_types: Vec::new(),
    })
}

fn extend_schema_generic_facts(
    generic: &mut SchemaGenericFacts,
    concrete_origins: BTreeMap<TypeDescriptor, BTreeSet<SourceSpan>>,
    shapes: &BTreeMap<CanonicalPath, DeclaredShape>,
) -> Result<(), SchemaAnalysisError> {
    for (descriptor, origins) in concrete_origins {
        let path = descriptor
            .declared_path()
            .ok_or(SchemaAnalysisError::Invariant)?;
        let shape = shapes.get(path).ok_or(SchemaAnalysisError::Invariant)?;
        generic.instantiations.push(
            ConcreteInstantiation::new(
                TemplateKind::DeclaredType,
                shape_template_identity(path, shape)?,
                descriptor.immediate_members(),
                ConcreteIdentity::DeclaredType(descriptor.clone()),
            )
            .map_err(|_| SchemaAnalysisError::Invariant)?,
        );
        let declaration = match shape {
            DeclaredShape::Struct { declaration, .. } | DeclaredShape::Enum { declaration, .. } => {
                declaration
            }
        };
        generic.source_map.push(ConcreteSourceMapEntry::new(
            ConcreteIdentity::DeclaredType(descriptor.clone()),
            declaration.clone(),
            SourceOriginSet::canonicalize(origins.into_iter().collect()),
        ));
        generic.concrete_types.push(descriptor);
    }
    generic.instantiations.sort_by(|left, right| {
        (left.kind(), left.template(), left.arguments()).cmp(&(
            right.kind(),
            right.template(),
            right.arguments(),
        ))
    });
    generic
        .source_map
        .sort_by(|left, right| left.node().cmp(right.node()));
    generic.concrete_types.sort_by(|left, right| {
        left.canonical_string()
            .as_bytes()
            .cmp(right.canonical_string().as_bytes())
    });
    Ok(())
}

fn collect_entry(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    structure: &PackageStructure,
) -> Result<Option<EntryInventory>, SchemaAnalysisError> {
    let Some(symbol) = structure.symbols().iter().find(|symbol| {
        symbol.kind == SymbolKind::Function && symbol.path.as_str() == "crate::main"
    }) else {
        return Ok(None);
    };
    for (source_index, source) in sources.iter().enumerate() {
        let resolved = facts
            .get(source_index)
            .ok_or(SchemaAnalysisError::Invariant)?;
        for node in source
            .tree()
            .nodes()
            .iter()
            .filter(|node| matches!(node.form(), SyntaxForm::FunctionDeclaration))
        {
            if direct_identifier_span(source.tree(), node).as_ref() != Some(&symbol.span) {
                continue;
            }
            let parameter = node.children().iter().copied().find_map(|child| {
                let parameter = source.tree().node(child)?;
                if !matches!(parameter.form(), SyntaxForm::Parameter) {
                    return None;
                }
                direct_child_form(source.tree(), parameter, SyntaxForm::ValueType)
                    .and_then(|ty| resolved.get(&ty))
                    .map(|fact| fact.descriptor.clone())
            });
            let result = node
                .children()
                .iter()
                .copied()
                .rfind(|child| {
                    source
                        .tree()
                        .node(*child)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::ValueType))
                })
                .and_then(|ty| resolved.get(&ty))
                .map_or(TypeDescriptor::UNIT, |fact| fact.descriptor.clone());
            return Ok(Some(EntryInventory {
                path: symbol.path.clone(),
                parameter,
                result,
            }));
        }
    }
    Ok(None)
}

fn collect_declared_shapes(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    generic_facts: &[GenericTypeFact],
    binders: &[TypeBinder],
    symbols_by_span: &BTreeMap<SourceSpan, &Symbol>,
    symbols_by_id: &BTreeMap<crate::SymbolId, &Symbol>,
    references: &BTreeMap<SourceSpan, crate::SymbolId>,
) -> Result<BTreeMap<CanonicalPath, DeclaredShape>, SchemaAnalysisError> {
    let generic_by_span = generic_facts
        .iter()
        .map(|fact| (fact.span.clone(), &fact.expression))
        .collect::<BTreeMap<_, _>>();
    let binders_by_declaration = binders
        .iter()
        .map(|binder| (binder.declaration.clone(), binder))
        .collect::<BTreeMap<_, _>>();
    let mut shapes = BTreeMap::new();
    for (source_index, source) in sources.iter().enumerate() {
        let resolved = facts
            .get(source_index)
            .ok_or(SchemaAnalysisError::Invariant)?;
        for (index, node) in source
            .tree()
            .nodes()
            .iter()
            .enumerate()
            .filter(|(_, node)| {
                matches!(
                    node.form(),
                    SyntaxForm::StructDeclaration | SyntaxForm::EnumDeclaration
                )
            })
        {
            let span = direct_identifier_span(source.tree(), node)
                .ok_or(SchemaAnalysisError::Invariant)?;
            let Some(symbol) = symbols_by_span.get(&span).copied() else {
                continue;
            };
            let binder = binders_by_declaration.get(node.span()).copied();
            let required = binder
                .into_iter()
                .flat_map(|binder| {
                    binder.parameters.iter().map(|parameter| TypeParameterKey {
                        binder_depth: binder.depth,
                        ordinal: parameter.ordinal,
                    })
                })
                .collect::<Vec<_>>();
            let predicates = collect_where_predicates(
                source.tree(),
                NodeId::from_index(index),
                binder,
                &generic_by_span,
                references,
                symbols_by_id,
            )?;
            let shape = match node.form() {
                SyntaxForm::StructDeclaration => {
                    let mut fields = Vec::new();
                    for child in node.children().iter().copied() {
                        let field = source
                            .tree()
                            .node(child)
                            .ok_or(SchemaAnalysisError::Invariant)?;
                        if !matches!(field.form(), SyntaxForm::StructField) {
                            continue;
                        }
                        let name = direct_identifier(source.tree(), field)
                            .ok_or(SchemaAnalysisError::Invariant)?;
                        let ty_id = direct_child_form(source.tree(), field, SyntaxForm::ValueType)
                            .ok_or(SchemaAnalysisError::Invariant)?;
                        let ty_node = source
                            .tree()
                            .node(ty_id)
                            .ok_or(SchemaAnalysisError::Invariant)?;
                        let ty = generic_by_span
                            .get(ty_node.span())
                            .cloned()
                            .cloned()
                            .or_else(|| {
                                resolved.get(&ty_id).and_then(|fact| {
                                    TypeExpression::closed(&fact.descriptor, u64::MAX).ok()
                                })
                            })
                            .ok_or(SchemaAnalysisError::Invariant)?;
                        let default = field_default_json(source.tree(), field)?;
                        fields.push(StructField { name, ty, default });
                    }
                    DeclaredShape::Struct {
                        declaration: node.span().clone(),
                        required,
                        predicates,
                        fields,
                    }
                }
                SyntaxForm::EnumDeclaration => {
                    let mut variants = Vec::new();
                    for child in node.children().iter().copied() {
                        let variant = source
                            .tree()
                            .node(child)
                            .ok_or(SchemaAnalysisError::Invariant)?;
                        if !matches!(variant.form(), SyntaxForm::EnumVariant) {
                            continue;
                        }
                        let name = direct_identifier(source.tree(), variant)
                            .ok_or(SchemaAnalysisError::Invariant)?;
                        let payload =
                            direct_child_form(source.tree(), variant, SyntaxForm::ValueType)
                                .map(|id| {
                                    let ty_node = source
                                        .tree()
                                        .node(id)
                                        .ok_or(SchemaAnalysisError::Invariant)?;
                                    generic_by_span
                                        .get(ty_node.span())
                                        .cloned()
                                        .cloned()
                                        .or_else(|| {
                                            resolved.get(&id).and_then(|fact| {
                                                TypeExpression::closed(&fact.descriptor, u64::MAX)
                                                    .ok()
                                            })
                                        })
                                        .ok_or(SchemaAnalysisError::Invariant)
                                })
                                .transpose()?;
                        variants.push((name, payload));
                    }
                    DeclaredShape::Enum {
                        declaration: node.span().clone(),
                        required,
                        predicates,
                        variants,
                    }
                }
                _ => return Err(SchemaAnalysisError::Invariant),
            };
            shapes.insert(symbol.path.clone(), shape);
        }
    }
    Ok(shapes)
}

fn public_declared_shapes(
    shapes: &BTreeMap<CanonicalPath, DeclaredShape>,
) -> Result<DeclaredValueShapes, SchemaAnalysisError> {
    let mut public = BTreeMap::new();
    for (path, shape) in shapes {
        let required = match shape {
            DeclaredShape::Struct { required, .. } | DeclaredShape::Enum { required, .. } => {
                required
            }
        };
        if !required.is_empty() {
            continue;
        }
        let concrete = instantiate_declared_shape(&TypeDescriptor::declared(path.clone()), shapes)?;
        let shape = match concrete {
            ConcreteDeclaredShape::Struct(fields) => DeclaredValueShape::Struct(
                fields
                    .into_iter()
                    .map(|field| DeclaredStructField {
                        name: field.name,
                        ty: field.ty,
                        default_json: field.default.map(|value| Arc::from(value.into_bytes())),
                    })
                    .collect(),
            ),
            ConcreteDeclaredShape::Enum(variants) => DeclaredValueShape::Enum(
                variants
                    .into_iter()
                    .map(|(name, payload)| DeclaredEnumVariant { name, payload })
                    .collect(),
            ),
        };
        public.insert(path.clone(), shape);
    }
    Ok(DeclaredValueShapes::new(public))
}

fn instantiate_declared_shape(
    descriptor: &TypeDescriptor,
    shapes: &BTreeMap<CanonicalPath, DeclaredShape>,
) -> Result<ConcreteDeclaredShape, SchemaAnalysisError> {
    let path = descriptor
        .declared_path()
        .ok_or(SchemaAnalysisError::Invariant)?;
    let shape = shapes.get(path).ok_or(SchemaAnalysisError::Invariant)?;
    let required = match shape {
        DeclaredShape::Struct { required, .. } | DeclaredShape::Enum { required, .. } => required,
    };
    let substitution = ExactTypeSubstitution::explicit(required, &descriptor.immediate_members())
        .map_err(|_| SchemaAnalysisError::Invariant)?;
    match shape {
        DeclaredShape::Struct { fields, .. } => fields
            .iter()
            .map(|field| {
                Ok(ConcreteStructField {
                    name: Arc::clone(&field.name),
                    ty: substitution
                        .apply(&field.ty)
                        .map_err(|_| SchemaAnalysisError::Invariant)?,
                    default: field.default.clone(),
                })
            })
            .collect::<Result<Vec<_>, SchemaAnalysisError>>()
            .map(ConcreteDeclaredShape::Struct),
        DeclaredShape::Enum { variants, .. } => variants
            .iter()
            .map(|(name, payload)| {
                let payload = payload
                    .as_ref()
                    .map(|ty| {
                        substitution
                            .apply(ty)
                            .map_err(|_| SchemaAnalysisError::Invariant)
                    })
                    .transpose()?;
                Ok((Arc::clone(name), payload))
            })
            .collect::<Result<Vec<_>, SchemaAnalysisError>>()
            .map(ConcreteDeclaredShape::Enum),
    }
}

fn build_root_schema(
    root: &TypeDescriptor,
    shapes: &BTreeMap<CanonicalPath, DeclaredShape>,
) -> Result<(String, BTreeSet<TypeDescriptor>), SchemaAnalysisError> {
    let reachable = reachable_declarations(root, shapes)?;
    let mut definitions = BTreeMap::<String, String>::new();
    let mut identities = BTreeMap::<String, String>::new();
    for descriptor in &reachable {
        let canonical = descriptor.canonical_string();
        let key = format!("{:x}", Sha256::digest(canonical.as_bytes()));
        if identities
            .insert(key.clone(), canonical.clone())
            .is_some_and(|prior| prior != canonical)
        {
            return Err(SchemaAnalysisError::Invariant);
        }
        let shape = instantiate_declared_shape(descriptor, shapes)?;
        definitions.insert(key, declared_definition(&shape, shapes)?);
    }
    let fragment = schema_fragment(root, shapes)?;
    let defs = encode_string_object(&definitions);
    let schema = json_string(DIALECT);
    if root.kind() == TypeKind::Declared {
        let reference = fragment
            .strip_prefix("{\"$ref\":")
            .and_then(|value| value.strip_suffix('}'))
            .ok_or(SchemaAnalysisError::Invariant)?;
        Ok((
            format!("{{\"$defs\":{defs},\"$ref\":{reference},\"$schema\":{schema}}}"),
            reachable,
        ))
    } else {
        let inner = fragment
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
            .ok_or(SchemaAnalysisError::Invariant)?;
        if definitions.is_empty() {
            Ok((format!("{{\"$schema\":{schema},{inner}}}"), reachable))
        } else {
            Ok((
                format!("{{\"$defs\":{defs},\"$schema\":{schema},{inner}}}"),
                reachable,
            ))
        }
    }
}

fn reachable_declarations(
    root: &TypeDescriptor,
    shapes: &BTreeMap<CanonicalPath, DeclaredShape>,
) -> Result<BTreeSet<TypeDescriptor>, SchemaAnalysisError> {
    let mut reachable = BTreeSet::new();
    let mut work = vec![root.clone()];
    while let Some(ty) = work.pop() {
        if ty.declared_path().is_some() {
            if !reachable.insert(ty.clone()) {
                continue;
            }
            match instantiate_declared_shape(&ty, shapes)? {
                ConcreteDeclaredShape::Struct(fields) => {
                    work.extend(fields.iter().map(|field| field.ty.clone()));
                }
                ConcreteDeclaredShape::Enum(variants) => {
                    work.extend(variants.iter().filter_map(|(_, ty)| ty.clone()));
                }
            }
        } else {
            work.extend(ty.immediate_members());
        }
    }
    Ok(reachable)
}

fn schema_fragment(
    root: &TypeDescriptor,
    shapes: &BTreeMap<CanonicalPath, DeclaredShape>,
) -> Result<String, SchemaAnalysisError> {
    let mut built = BTreeMap::<TypeDescriptor, String>::new();
    let mut work = vec![(root.clone(), false)];
    while let Some((ty, expanded)) = work.pop() {
        if built.contains_key(&ty) {
            continue;
        }
        if !expanded && ty.declared_path().is_none() && !ty.immediate_members().is_empty() {
            work.push((ty.clone(), true));
            for member in ty.immediate_members().into_iter().rev() {
                work.push((member, false));
            }
            continue;
        }
        let members = if ty.declared_path().is_some() {
            Vec::new()
        } else {
            ty.immediate_members()
                .into_iter()
                .map(|member| {
                    built
                        .get(&member)
                        .cloned()
                        .ok_or(SchemaAnalysisError::Invariant)
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let value = match ty.kind() {
            TypeKind::Unit => "{\"type\":\"null\"}".to_owned(),
            TypeKind::Bool => "{\"type\":\"boolean\"}".to_owned(),
            TypeKind::Int => "{\"maximum\":9007199254740991,\"minimum\":-9007199254740991,\"type\":\"integer\"}".to_owned(),
            TypeKind::Float => "{\"maximum\":1.7976931348623157e+308,\"minimum\":-1.7976931348623157e+308,\"type\":\"number\"}".to_owned(),
            TypeKind::String => "{\"type\":\"string\"}".to_owned(),
            TypeKind::Decision => "{\"additionalProperties\":false,\"properties\":{\"decision\":{\"type\":\"boolean\"},\"rationale\":{\"minLength\":1,\"type\":\"string\"}},\"required\":[\"decision\",\"rationale\"],\"type\":\"object\"}".to_owned(),
            TypeKind::OperationError => operation_error_schema(),
            TypeKind::Declared => {
                let path = ty.declared_path().ok_or(SchemaAnalysisError::Invariant)?;
                if !shapes.contains_key(path) {
                    return Err(SchemaAnalysisError::Invariant);
                }
                format!("{{\"$ref\":\"#/$defs/{}\"}}", definition_key(&ty))
            }
            TypeKind::Option => format!(
                "{{\"anyOf\":[{{\"type\":\"null\"}},{}]}}",
                members.first().ok_or(SchemaAnalysisError::Invariant)?
            ),
            TypeKind::Result => format!(
                "{{\"oneOf\":[{},{}]}}",
                payload_schema("Ok", members.first().ok_or(SchemaAnalysisError::Invariant)?),
                payload_schema("Err", members.get(1).ok_or(SchemaAnalysisError::Invariant)?)
            ),
            TypeKind::List => format!(
                "{{\"items\":{},\"type\":\"array\"}}",
                members.first().ok_or(SchemaAnalysisError::Invariant)?
            ),
            TypeKind::Tuple => {
                let count = members.len();
                format!(
                    "{{\"items\":false,\"maxItems\":{count},\"minItems\":{count},\"prefixItems\":[{}],\"type\":\"array\"}}",
                    members.join(",")
                )
            }
        };
        built.insert(ty, value);
    }
    built.remove(root).ok_or(SchemaAnalysisError::Invariant)
}

fn declared_definition(
    shape: &ConcreteDeclaredShape,
    shapes: &BTreeMap<CanonicalPath, DeclaredShape>,
) -> Result<String, SchemaAnalysisError> {
    match shape {
        ConcreteDeclaredShape::Struct(fields) => {
            let mut properties = fields
                .iter()
                .map(|field| {
                    let mut schema = schema_fragment(&field.ty, shapes)?;
                    if let Some(default) = &field.default {
                        let inner = schema
                            .strip_prefix('{')
                            .and_then(|value| value.strip_suffix('}'))
                            .ok_or(SchemaAnalysisError::Invariant)?;
                        schema = format!("{{{inner},\"default\":{default}}}");
                    }
                    Ok((field.name.clone(), schema))
                })
                .collect::<Result<Vec<_>, SchemaAnalysisError>>()?;
            properties.sort_by(|left, right| utf16_cmp(&left.0, &right.0));
            let properties = properties
                .into_iter()
                .map(|(name, schema)| format!("{}:{schema}", json_string(&name)))
                .collect::<Vec<_>>()
                .join(",");
            let required = fields
                .iter()
                .filter(|field| field.ty.kind() != TypeKind::Option)
                .map(|field| json_string(&field.name))
                .collect::<Vec<_>>()
                .join(",");
            Ok(format!(
                "{{\"additionalProperties\":false,\"properties\":{{{properties}}},\"required\":[{required}],\"type\":\"object\"}}"
            ))
        }
        ConcreteDeclaredShape::Enum(variants) => {
            let branches = variants
                .iter()
                .map(|(name, payload)| match payload {
                    Some(ty) => {
                        schema_fragment(ty, shapes).map(|schema| payload_schema(name, &schema))
                    }
                    None => Ok(unit_variant_schema(name)),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("{{\"oneOf\":[{}]}}", branches.join(",")))
        }
    }
}

fn operation_error_schema() -> String {
    let string = "{\"type\":\"string\"}";
    let tuple = "{\"items\":false,\"maxItems\":2,\"minItems\":2,\"prefixItems\":[{\"type\":\"string\"},{\"type\":\"string\"}],\"type\":\"array\"}";
    let branches = [
        payload_schema("Declined", string),
        unit_variant_schema("InvalidOutput"),
        payload_schema("ProviderFailure", string),
        payload_schema("Timeout", string),
        payload_schema("PolicyDenied", string),
        payload_schema("Cancelled", string),
        payload_schema("UnknownOutcome", tuple),
    ];
    format!("{{\"oneOf\":[{}]}}", branches.join(","))
}

fn payload_schema(name: &str, payload: &str) -> String {
    format!(
        "{{\"additionalProperties\":false,\"properties\":{{\"value\":{payload},\"variant\":{{\"const\":{},\"type\":\"string\"}}}},\"required\":[\"variant\",\"value\"],\"type\":\"object\"}}",
        json_string(name)
    )
}

fn unit_variant_schema(name: &str) -> String {
    format!(
        "{{\"additionalProperties\":false,\"properties\":{{\"variant\":{{\"const\":{},\"type\":\"string\"}}}},\"required\":[\"variant\"],\"type\":\"object\"}}",
        json_string(name)
    )
}

fn definition_key(descriptor: &TypeDescriptor) -> String {
    format!(
        "{:x}",
        Sha256::digest(descriptor.canonical_string().as_bytes())
    )
}

fn encode_string_object(values: &BTreeMap<String, String>) -> String {
    let body = values
        .iter()
        .map(|(key, value)| format!("{}:{value}", json_string(key)))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{body}}}")
}

fn field_default_json(
    tree: &SyntaxTree,
    field: &gantry_frontend::SyntaxNode,
) -> Result<Option<String>, SchemaAnalysisError> {
    let Some(equal) = field.children().iter().position(|child| {
        tree.node(*child).is_some_and(|node| {
            matches!(
                node.form(),
                SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Equal))
            )
        })
    }) else {
        return Ok(None);
    };
    let tokens = field
        .children()
        .get(equal.saturating_add(1)..)
        .unwrap_or_default()
        .iter()
        .filter_map(|child| tree.node(*child))
        .collect::<Vec<_>>();
    let negative = tokens.iter().any(|node| {
        matches!(
            node.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Minus))
        )
    });
    for token in tokens {
        let value = match token.form() {
            SyntaxForm::Token(TokenKind::IntegerLiteral(value)) => {
                let digits = value.replace('_', "");
                let parsed = digits
                    .parse::<i64>()
                    .map_err(|_| SchemaAnalysisError::Invariant)?;
                Some(if negative { -parsed } else { parsed }.to_string())
            }
            SyntaxForm::Token(TokenKind::FloatLiteral(value)) => {
                let parsed = value
                    .replace('_', "")
                    .parse::<f64>()
                    .map_err(|_| SchemaAnalysisError::Invariant)?;
                let parsed = if negative { -parsed } else { parsed };
                Some(if parsed == 0.0 {
                    "0".to_owned()
                } else {
                    parsed.to_string()
                })
            }
            SyntaxForm::Token(
                TokenKind::StringLiteral(value) | TokenKind::RawStringLiteral(value),
            ) => Some(json_string(value)),
            SyntaxForm::Token(TokenKind::ReservedWord(word)) => match word.spelling() {
                "true" | "false" => Some(word.spelling().to_owned()),
                "None" => Some("null".to_owned()),
                _ => None,
            },
            _ => None,
        };
        if value.is_some() {
            return Ok(value);
        }
    }
    Ok(Some("null".to_owned()))
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{1f}' => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
    output
}

fn direct_child_form(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    form: SyntaxForm,
) -> Option<NodeId> {
    node.children().iter().copied().find(|child| {
        tree.node(*child).is_some_and(|node| {
            std::mem::discriminant(node.form()) == std::mem::discriminant(&form)
        })
    })
}

fn direct_identifier_span(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Option<SourceSpan> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::Identifier(_)) => Some(child.span().clone()),
            _ => None,
        })
}

fn direct_identifier(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> Option<Arc<str>> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
            _ => None,
        })
}

impl From<AnalysisError> for SchemaAnalysisError {
    fn from(_: AnalysisError) -> Self {
        Self::Invariant
    }
}
