//! Canonical generated schemas and entry-boundary inventories.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::source::{FrontendResourceLimit, SourceSpan};
use gantry_frontend::{NodeId, ParsedSource, Punctuation, SyntaxForm, SyntaxTree, TokenKind};
use gantry_ir::generated::TypeKind;
use gantry_ir::{
    ArtifactEncodingError, ArtifactLimits, CanonicalPath, EntryInventory, GeneratedSchemaObject,
    SchemaObjectError, TypeDescriptor, WorkflowFacts,
};
use sha2::{Digest, Sha256};

use crate::{
    AnalysisError, DeclaredEnumVariant, DeclaredStructField, DeclaredValueShape,
    DeclaredValueShapes, PackageStructure, Symbol, SymbolKind, TypeFact,
};

const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

#[derive(Clone, Debug)]
struct StructField {
    name: Arc<str>,
    ty: TypeDescriptor,
    default: Option<String>,
}

#[derive(Clone, Debug)]
enum DeclaredShape {
    Struct(Vec<StructField>),
    Enum(Vec<(Arc<str>, Option<TypeDescriptor>)>),
}

pub(crate) enum SchemaAnalysisError {
    ResourceLimit(FrontendResourceLimit),
    Invariant,
}

pub(crate) fn analyze_generated_schemas(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    structure: &PackageStructure,
    workflows: &[WorkflowFacts],
    limits: ArtifactLimits,
) -> Result<
    (
        Option<EntryInventory>,
        Option<GeneratedSchemaObject>,
        DeclaredValueShapes,
    ),
    SchemaAnalysisError,
> {
    let symbols_by_span = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.span.clone(), symbol))
        .collect::<BTreeMap<_, _>>();
    let shapes = collect_declared_shapes(sources, facts, &symbols_by_span)?;
    let entry = collect_entry(sources, facts, structure)?;
    let mut roots = BTreeMap::<String, TypeDescriptor>::new();
    if let Some(entry) = &entry {
        if let Some(parameter) = &entry.parameter {
            roots.insert(parameter.canonical_string(), parameter.clone());
        }
        roots.insert(entry.result.canonical_string(), entry.result.clone());
    }
    for operation in workflows.iter().flat_map(|workflow| &workflow.operations) {
        roots.insert(
            operation.result.canonical_string(),
            operation.result.clone(),
        );
    }
    if roots.is_empty() {
        return Ok((entry, None, public_declared_shapes(&shapes)));
    }

    let mut entries = Vec::with_capacity(roots.len());
    for root in roots.into_values() {
        let schema = build_root_schema(&root, &shapes)?;
        entries.push((root, Arc::from(schema.into_bytes())));
    }
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
    Ok((entry, Some(schemas), public_declared_shapes(&shapes)))
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
    symbols_by_span: &BTreeMap<SourceSpan, &Symbol>,
) -> Result<BTreeMap<CanonicalPath, DeclaredShape>, SchemaAnalysisError> {
    let mut shapes = BTreeMap::new();
    for (source_index, source) in sources.iter().enumerate() {
        let resolved = facts
            .get(source_index)
            .ok_or(SchemaAnalysisError::Invariant)?;
        for node in source.tree().nodes().iter().filter(|node| {
            matches!(
                node.form(),
                SyntaxForm::StructDeclaration | SyntaxForm::EnumDeclaration
            )
        }) {
            let span = direct_identifier_span(source.tree(), node)
                .ok_or(SchemaAnalysisError::Invariant)?;
            let Some(symbol) = symbols_by_span.get(&span).copied() else {
                continue;
            };
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
                        let ty = direct_child_form(source.tree(), field, SyntaxForm::ValueType)
                            .and_then(|id| resolved.get(&id))
                            .map(|fact| fact.descriptor.clone())
                            .ok_or(SchemaAnalysisError::Invariant)?;
                        let default = (ty.kind() == TypeKind::Option)
                            .then(|| field_default_json(source.tree(), field))
                            .transpose()?
                            .flatten();
                        fields.push(StructField { name, ty, default });
                    }
                    DeclaredShape::Struct(fields)
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
                                .and_then(|id| resolved.get(&id))
                                .map(|fact| fact.descriptor.clone());
                        variants.push((name, payload));
                    }
                    DeclaredShape::Enum(variants)
                }
                _ => return Err(SchemaAnalysisError::Invariant),
            };
            shapes.insert(symbol.path.clone(), shape);
        }
    }
    Ok(shapes)
}

fn public_declared_shapes(shapes: &BTreeMap<CanonicalPath, DeclaredShape>) -> DeclaredValueShapes {
    DeclaredValueShapes::new(
        shapes
            .iter()
            .map(|(path, shape)| {
                let shape = match shape {
                    DeclaredShape::Struct(fields) => DeclaredValueShape::Struct(
                        fields
                            .iter()
                            .map(|field| DeclaredStructField {
                                name: Arc::clone(&field.name),
                                ty: field.ty.clone(),
                                default_json: field
                                    .default
                                    .as_ref()
                                    .map(|value| Arc::from(value.as_bytes())),
                            })
                            .collect(),
                    ),
                    DeclaredShape::Enum(variants) => DeclaredValueShape::Enum(
                        variants
                            .iter()
                            .map(|(name, payload)| DeclaredEnumVariant {
                                name: Arc::clone(name),
                                payload: payload.clone(),
                            })
                            .collect(),
                    ),
                };
                (path.clone(), shape)
            })
            .collect(),
    )
}

fn build_root_schema(
    root: &TypeDescriptor,
    shapes: &BTreeMap<CanonicalPath, DeclaredShape>,
) -> Result<String, SchemaAnalysisError> {
    let reachable = reachable_declarations(root, shapes)?;
    let mut definitions = BTreeMap::<String, String>::new();
    let mut identities = BTreeMap::<String, String>::new();
    for path in reachable {
        let descriptor = TypeDescriptor::declared(path.clone());
        let canonical = descriptor.canonical_string();
        let key = format!("{:x}", Sha256::digest(canonical.as_bytes()));
        if identities
            .insert(key.clone(), canonical.clone())
            .is_some_and(|prior| prior != canonical)
        {
            return Err(SchemaAnalysisError::Invariant);
        }
        let shape = shapes.get(&path).ok_or(SchemaAnalysisError::Invariant)?;
        definitions.insert(key, declared_definition(shape, shapes)?);
    }
    let fragment = schema_fragment(root, shapes)?;
    let defs = encode_string_object(&definitions);
    let schema = json_string(DIALECT);
    if root.kind() == TypeKind::Declared {
        let reference = fragment
            .strip_prefix("{\"$ref\":")
            .and_then(|value| value.strip_suffix('}'))
            .ok_or(SchemaAnalysisError::Invariant)?;
        Ok(format!(
            "{{\"$defs\":{defs},\"$ref\":{reference},\"$schema\":{schema}}}"
        ))
    } else {
        let inner = fragment
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
            .ok_or(SchemaAnalysisError::Invariant)?;
        if definitions.is_empty() {
            Ok(format!("{{\"$schema\":{schema},{inner}}}"))
        } else {
            Ok(format!("{{\"$defs\":{defs},\"$schema\":{schema},{inner}}}"))
        }
    }
}

fn reachable_declarations(
    root: &TypeDescriptor,
    shapes: &BTreeMap<CanonicalPath, DeclaredShape>,
) -> Result<BTreeSet<CanonicalPath>, SchemaAnalysisError> {
    let mut reachable = BTreeSet::new();
    let mut work = vec![root.clone()];
    while let Some(ty) = work.pop() {
        if let Some(path) = ty.declared_path() {
            if !reachable.insert(path.clone()) {
                continue;
            }
            match shapes.get(path).ok_or(SchemaAnalysisError::Invariant)? {
                DeclaredShape::Struct(fields) => {
                    work.extend(fields.iter().map(|field| field.ty.clone()));
                }
                DeclaredShape::Enum(variants) => {
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
        let members = ty
            .immediate_members()
            .into_iter()
            .map(|member| {
                built
                    .get(&member)
                    .cloned()
                    .ok_or(SchemaAnalysisError::Invariant)
            })
            .collect::<Result<Vec<_>, _>>()?;
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
                format!("{{\"$ref\":\"#/$defs/{}\"}}", definition_key(path))
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
    shape: &DeclaredShape,
    shapes: &BTreeMap<CanonicalPath, DeclaredShape>,
) -> Result<String, SchemaAnalysisError> {
    match shape {
        DeclaredShape::Struct(fields) => {
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
        DeclaredShape::Enum(variants) => {
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

fn definition_key(path: &CanonicalPath) -> String {
    let descriptor = TypeDescriptor::declared(path.clone()).canonical_string();
    format!("{:x}", Sha256::digest(descriptor.as_bytes()))
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
