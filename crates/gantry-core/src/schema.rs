//! Iterative validation for the generated Gantry Draft 2020-12 schema subset.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::canonical_json::{CanonicalJson, CanonicalJsonError};
use crate::strict_json::{JsonError, JsonLimits, JsonNode, JsonNodeId, StrictJsonDocument};

/// One deterministic generated-schema validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    /// JSON Pointer locating the failing instance value.
    pub instance_location: Arc<str>,
    /// JSON Pointer locating the violated schema keyword.
    pub schema_location: Arc<str>,
    /// Disclosure-neutral human-readable failure description.
    pub message: Arc<str>,
}

/// Failure while admitting or evaluating a generated schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchemaError {
    /// The schema bytes are not strict JSON.
    Json(JsonError),
    /// A schema node does not have the generated subset's required shape.
    InvalidSchema {
        /// JSON Pointer locating the malformed schema node.
        location: Arc<str>,
    },
    /// A local `$ref` does not resolve to one retained `$defs` member.
    InvalidReference {
        /// Exact unsupported or unresolved reference.
        reference: Arc<str>,
    },
    /// Validation encountered a reference cycle that did not consume instance structure.
    ReferenceCycle,
}

/// Failure while validating and canonically normalizing one generated-schema value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizationError {
    /// The admitted instance violates its generated schema.
    Validation(Vec<ValidationError>),
    /// The generated schema could not be evaluated.
    Schema(SchemaError),
    /// The complete normalized value violates an effective JSON/value limit.
    Json(JsonError),
    /// The normalized exact-number tree cannot be represented canonically.
    Canonical(CanonicalJsonError),
}

/// One admitted generated schema ready to validate strict JSON instances.
#[derive(Clone, Debug)]
pub struct SchemaValidator {
    schema: StrictJsonDocument,
    definitions: BTreeMap<Arc<str>, JsonNodeId>,
}

impl SchemaValidator {
    /// Parses one generated Draft 2020-12 schema and indexes local definitions.
    pub fn compile(bytes: impl Into<Arc<[u8]>>, limits: JsonLimits) -> Result<Self, SchemaError> {
        let schema = StrictJsonDocument::decode(bytes, limits).map_err(SchemaError::Json)?;
        let root = object(&schema, schema.root()).ok_or_else(|| SchemaError::InvalidSchema {
            location: Arc::from(""),
        })?;
        let mut definitions = BTreeMap::new();
        if let Some(definitions_id) = member(root, "$defs") {
            let values =
                object(&schema, definitions_id).ok_or_else(|| SchemaError::InvalidSchema {
                    location: Arc::from("/$defs"),
                })?;
            for (name, id) in values {
                if object(&schema, *id).is_none() {
                    return Err(SchemaError::InvalidSchema {
                        location: Arc::from(format!("/$defs/{}", pointer_component(name))),
                    });
                }
                definitions.insert(name.clone(), *id);
            }
        }
        Ok(Self {
            schema,
            definitions,
        })
    }

    /// Validates one admitted strict JSON instance against the complete schema.
    pub fn validate(
        &self,
        instance: &StrictJsonDocument,
    ) -> Result<Vec<ValidationError>, SchemaError> {
        self.validate_node_from(instance, instance.root(), self.schema.root())
    }

    /// Validates and normalizes one strict JSON value into canonical Gantry JSON.
    ///
    /// Omitted optional object properties are materialized from their generated
    /// schema default or as JSON `null`. Validation and normalization complete
    /// before any bytes are returned.
    pub fn normalize(
        &self,
        instance: &StrictJsonDocument,
        limits: JsonLimits,
    ) -> Result<CanonicalJson, NormalizationError> {
        let errors = self
            .validate(instance)
            .map_err(NormalizationError::Schema)?;
        if !errors.is_empty() {
            return Err(NormalizationError::Validation(errors));
        }
        let bytes = self
            .normalize_valid(instance)
            .map_err(NormalizationError::Schema)?;
        let normalized =
            StrictJsonDocument::decode(bytes, limits).map_err(NormalizationError::Json)?;
        CanonicalJson::from_document(&normalized).map_err(NormalizationError::Canonical)
    }

    fn normalize_valid(&self, instance: &StrictJsonDocument) -> Result<Vec<u8>, SchemaError> {
        let mut output = Vec::new();
        let mut work = vec![NormalizeTask::Instance {
            schema: self.schema.root(),
            instance: instance.root(),
        }];
        while let Some(task) = work.pop() {
            match task {
                NormalizeTask::Byte(byte) => output.push(byte),
                NormalizeTask::Null => output.extend_from_slice(b"null"),
                NormalizeTask::String(value) => push_json_string(&mut output, &value),
                NormalizeTask::Raw { document, node } => {
                    self.expand_raw(instance, document, node, &mut output, &mut work)?;
                }
                NormalizeTask::Instance {
                    schema,
                    instance: instance_id,
                } => {
                    let schema = self.normalization_schema(instance, instance_id, schema)?;
                    let schema_object =
                        object(&self.schema, schema).ok_or_else(|| SchemaError::InvalidSchema {
                            location: Arc::from(""),
                        })?;
                    match instance
                        .node(instance_id)
                        .ok_or_else(|| SchemaError::InvalidSchema {
                            location: Arc::from(""),
                        })? {
                        JsonNode::Array(items) => {
                            let prefix = member(schema_object, "prefixItems")
                                .map(|id| {
                                    array(&self.schema, id).ok_or_else(|| {
                                        SchemaError::InvalidSchema {
                                            location: Arc::from("/prefixItems"),
                                        }
                                    })
                                })
                                .transpose()?
                                .unwrap_or_default();
                            let item_schema = member(schema_object, "items");
                            output.push(b'[');
                            work.push(NormalizeTask::Byte(b']'));
                            let mut sequence = Vec::with_capacity(items.len().saturating_mul(2));
                            for (index, item) in items.iter().copied().enumerate() {
                                if index > 0 {
                                    sequence.push(NormalizeTask::Byte(b','));
                                }
                                let child_schema =
                                    prefix.get(index).copied().or(item_schema).ok_or_else(
                                        || SchemaError::InvalidSchema {
                                            location: Arc::from("/items"),
                                        },
                                    )?;
                                sequence.push(NormalizeTask::Instance {
                                    schema: child_schema,
                                    instance: item,
                                });
                            }
                            work.extend(sequence.into_iter().rev());
                        }
                        JsonNode::Object(values) => {
                            let properties = member(schema_object, "properties")
                                .map(|id| {
                                    object(&self.schema, id).ok_or_else(|| {
                                        SchemaError::InvalidSchema {
                                            location: Arc::from("/properties"),
                                        }
                                    })
                                })
                                .transpose()?
                                .unwrap_or_default();
                            let required = member(schema_object, "required")
                                .map(|id| schema_string_set(&self.schema, id, "", "required"))
                                .transpose()?
                                .unwrap_or_default();
                            let present = values
                                .iter()
                                .map(|(name, id)| (name.as_ref(), *id))
                                .collect::<BTreeMap<_, _>>();
                            let property_names = properties
                                .iter()
                                .map(|(name, _)| name.as_ref())
                                .collect::<BTreeSet<_>>();
                            let mut fields = Vec::<(Arc<str>, NormalizeTask)>::new();
                            for (name, property_schema) in properties {
                                if let Some(value) = present.get(name.as_ref()) {
                                    fields.push((
                                        name.clone(),
                                        NormalizeTask::Instance {
                                            schema: *property_schema,
                                            instance: *value,
                                        },
                                    ));
                                } else if !required.contains(name) {
                                    let value = object(&self.schema, *property_schema)
                                        .and_then(|schema| member(schema, "default"))
                                        .map_or(NormalizeTask::Null, |node| NormalizeTask::Raw {
                                            document: NormalizeDocument::Schema,
                                            node,
                                        });
                                    fields.push((name.clone(), value));
                                }
                            }
                            for (name, value) in values {
                                if !property_names.contains(name.as_ref()) {
                                    fields.push((
                                        name.clone(),
                                        NormalizeTask::Raw {
                                            document: NormalizeDocument::Instance,
                                            node: *value,
                                        },
                                    ));
                                }
                            }
                            output.push(b'{');
                            work.push(NormalizeTask::Byte(b'}'));
                            let mut sequence = Vec::with_capacity(fields.len().saturating_mul(4));
                            for (index, (name, value)) in fields.into_iter().enumerate() {
                                if index > 0 {
                                    sequence.push(NormalizeTask::Byte(b','));
                                }
                                sequence.push(NormalizeTask::String(name));
                                sequence.push(NormalizeTask::Byte(b':'));
                                sequence.push(value);
                            }
                            work.extend(sequence.into_iter().rev());
                        }
                        _ => work.push(NormalizeTask::Raw {
                            document: NormalizeDocument::Instance,
                            node: instance_id,
                        }),
                    }
                }
            }
        }
        Ok(output)
    }

    fn normalization_schema(
        &self,
        instance: &StrictJsonDocument,
        instance_id: JsonNodeId,
        mut schema_id: JsonNodeId,
    ) -> Result<JsonNodeId, SchemaError> {
        for _ in 0..=self.schema.nodes().len() {
            let schema =
                object(&self.schema, schema_id).ok_or_else(|| SchemaError::InvalidSchema {
                    location: Arc::from(""),
                })?;
            if let Some(reference_id) = member(schema, "$ref") {
                let reference = string(&self.schema, reference_id).ok_or_else(|| {
                    SchemaError::InvalidSchema {
                        location: Arc::from("/$ref"),
                    }
                })?;
                let key = reference
                    .strip_prefix("#/$defs/")
                    .and_then(decode_pointer_component)
                    .ok_or_else(|| SchemaError::InvalidReference {
                        reference: Arc::from(reference),
                    })?;
                schema_id = self.definitions.get(key.as_str()).copied().ok_or_else(|| {
                    SchemaError::InvalidReference {
                        reference: Arc::from(reference),
                    }
                })?;
                continue;
            }
            let branches = ["anyOf", "oneOf"]
                .into_iter()
                .find_map(|keyword| member(schema, keyword));
            let Some(branches) = branches else {
                return Ok(schema_id);
            };
            let branches =
                array(&self.schema, branches).ok_or_else(|| SchemaError::InvalidSchema {
                    location: Arc::from(""),
                })?;
            let mut matching_branch = None;
            for branch in branches.iter().copied() {
                if self
                    .validate_node_from(instance, instance_id, branch)?
                    .is_empty()
                {
                    matching_branch = Some(branch);
                    break;
                }
            }
            schema_id = matching_branch.ok_or_else(|| SchemaError::InvalidSchema {
                location: Arc::from(""),
            })?;
        }
        Err(SchemaError::ReferenceCycle)
    }

    fn expand_raw(
        &self,
        instance: &StrictJsonDocument,
        document: NormalizeDocument,
        node: JsonNodeId,
        output: &mut Vec<u8>,
        work: &mut Vec<NormalizeTask>,
    ) -> Result<(), SchemaError> {
        let document_ref = match document {
            NormalizeDocument::Instance => instance,
            NormalizeDocument::Schema => &self.schema,
        };
        match document_ref
            .node(node)
            .ok_or_else(|| SchemaError::InvalidSchema {
                location: Arc::from(""),
            })? {
            JsonNode::Null => output.extend_from_slice(b"null"),
            JsonNode::Bool(true) => output.extend_from_slice(b"true"),
            JsonNode::Bool(false) => output.extend_from_slice(b"false"),
            JsonNode::Number(number) => output.extend_from_slice(number.lexeme().as_bytes()),
            JsonNode::String(value) => push_json_string(output, value),
            JsonNode::Array(items) => {
                output.push(b'[');
                work.push(NormalizeTask::Byte(b']'));
                let mut sequence = Vec::with_capacity(items.len().saturating_mul(2));
                for (index, item) in items.iter().copied().enumerate() {
                    if index > 0 {
                        sequence.push(NormalizeTask::Byte(b','));
                    }
                    sequence.push(NormalizeTask::Raw {
                        document,
                        node: item,
                    });
                }
                work.extend(sequence.into_iter().rev());
            }
            JsonNode::Object(values) => {
                output.push(b'{');
                work.push(NormalizeTask::Byte(b'}'));
                let mut sequence = Vec::with_capacity(values.len().saturating_mul(4));
                for (index, (name, value)) in values.iter().enumerate() {
                    if index > 0 {
                        sequence.push(NormalizeTask::Byte(b','));
                    }
                    sequence.push(NormalizeTask::String(name.clone()));
                    sequence.push(NormalizeTask::Byte(b':'));
                    sequence.push(NormalizeTask::Raw {
                        document,
                        node: *value,
                    });
                }
                work.extend(sequence.into_iter().rev());
            }
        }
        Ok(())
    }

    fn validate_node_from(
        &self,
        instance: &StrictJsonDocument,
        instance_root: JsonNodeId,
        schema_root: JsonNodeId,
    ) -> Result<Vec<ValidationError>, SchemaError> {
        let mut work = vec![Task::Check {
            schema: schema_root,
            instance: instance_root,
            instance_path: Arc::from(""),
            schema_path: Arc::from(""),
        }];
        let mut results = Vec::<Outcome>::new();
        let schema_nodes = u64::try_from(self.schema.nodes().len()).ok();
        let instance_nodes = u64::try_from(instance.nodes().len()).ok();
        let maximum_steps = schema_nodes
            .and_then(|schema| instance_nodes.and_then(|instance| schema.checked_mul(instance)))
            .and_then(|steps| steps.checked_mul(16))
            .unwrap_or(u64::MAX)
            .max(1);
        let mut steps = 0_u64;

        while let Some(task) = work.pop() {
            match task {
                Task::Check {
                    schema,
                    instance: instance_id,
                    instance_path,
                    schema_path,
                } => {
                    steps = steps.checked_add(1).ok_or(SchemaError::ReferenceCycle)?;
                    if steps > maximum_steps {
                        return Err(SchemaError::ReferenceCycle);
                    }
                    self.expand_check(
                        instance,
                        schema,
                        instance_id,
                        instance_path,
                        schema_path,
                        &mut work,
                        &mut results,
                    )?;
                }
                Task::CombineAll { count, mut errors } => {
                    let children = take_outcomes(&mut results, count)?;
                    for child in children {
                        errors.extend(child.errors);
                    }
                    results.push(Outcome { errors });
                }
                Task::CombineBranches {
                    count,
                    exact_one,
                    instance_path,
                    schema_path,
                } => {
                    let children = take_outcomes(&mut results, count)?;
                    let valid = children
                        .iter()
                        .filter(|child| child.errors.is_empty())
                        .count();
                    let accepted = if exact_one { valid == 1 } else { valid > 0 };
                    let errors = if accepted {
                        Vec::new()
                    } else {
                        vec![validation_error(
                            instance_path,
                            schema_path,
                            if exact_one {
                                "instance must match exactly one schema branch"
                            } else {
                                "instance must match at least one schema branch"
                            },
                        )]
                    };
                    results.push(Outcome { errors });
                }
            }
        }

        if results.len() != 1 {
            return Err(SchemaError::InvalidSchema {
                location: Arc::from(""),
            });
        }
        Ok(results
            .pop()
            .unwrap_or_else(|| unreachable!("one result was checked"))
            .errors)
    }

    #[allow(clippy::too_many_arguments)]
    fn expand_check(
        &self,
        instance_document: &StrictJsonDocument,
        schema_id: JsonNodeId,
        instance_id: JsonNodeId,
        instance_path: Arc<str>,
        schema_path: Arc<str>,
        work: &mut Vec<Task>,
        results: &mut Vec<Outcome>,
    ) -> Result<(), SchemaError> {
        let schema = object(&self.schema, schema_id).ok_or_else(|| SchemaError::InvalidSchema {
            location: schema_path.clone(),
        })?;

        if let Some(reference_id) = member(schema, "$ref") {
            let reference =
                string(&self.schema, reference_id).ok_or_else(|| SchemaError::InvalidSchema {
                    location: join_pointer(&schema_path, "$ref"),
                })?;
            let key = reference.strip_prefix("#/$defs/").ok_or_else(|| {
                SchemaError::InvalidReference {
                    reference: Arc::from(reference),
                }
            })?;
            let key =
                decode_pointer_component(key).ok_or_else(|| SchemaError::InvalidReference {
                    reference: Arc::from(reference),
                })?;
            let target = self.definitions.get(key.as_str()).copied().ok_or_else(|| {
                SchemaError::InvalidReference {
                    reference: Arc::from(reference),
                }
            })?;
            work.push(Task::Check {
                schema: target,
                instance: instance_id,
                instance_path,
                schema_path: Arc::from(format!("/$defs/{}", pointer_component(&key))),
            });
            return Ok(());
        }

        for (keyword, exact_one) in [("anyOf", false), ("oneOf", true)] {
            if let Some(branches_id) = member(schema, keyword) {
                let branches =
                    array(&self.schema, branches_id).ok_or_else(|| SchemaError::InvalidSchema {
                        location: join_pointer(&schema_path, keyword),
                    })?;
                if branches.is_empty() {
                    return Err(SchemaError::InvalidSchema {
                        location: join_pointer(&schema_path, keyword),
                    });
                }
                work.push(Task::CombineBranches {
                    count: branches.len(),
                    exact_one,
                    instance_path: instance_path.clone(),
                    schema_path: join_pointer(&schema_path, keyword),
                });
                for (index, branch) in branches.iter().copied().enumerate().rev() {
                    work.push(Task::Check {
                        schema: branch,
                        instance: instance_id,
                        instance_path: instance_path.clone(),
                        schema_path: join_pointer(
                            &join_pointer(&schema_path, keyword),
                            &index.to_string(),
                        ),
                    });
                }
                return Ok(());
            }
        }

        let instance =
            instance_document
                .node(instance_id)
                .ok_or_else(|| SchemaError::InvalidSchema {
                    location: schema_path.clone(),
                })?;
        let mut errors = Vec::new();
        let mut children = Vec::<CheckSpec>::new();
        let type_matches = if let Some(type_id) = member(schema, "type") {
            let expected =
                string(&self.schema, type_id).ok_or_else(|| SchemaError::InvalidSchema {
                    location: join_pointer(&schema_path, "type"),
                })?;
            let valid = type_matches(instance, expected);
            if !valid {
                errors.push(validation_error(
                    instance_path.clone(),
                    join_pointer(&schema_path, "type"),
                    "instance has the wrong JSON type",
                ));
            }
            valid
        } else {
            true
        };

        if type_matches {
            self.check_const(
                instance_document,
                instance_id,
                schema,
                &instance_path,
                &schema_path,
                &mut errors,
            )?;
            self.check_number(instance, schema, &instance_path, &schema_path, &mut errors)?;
            self.check_string(instance, schema, &instance_path, &schema_path, &mut errors)?;
            self.check_array(
                instance_document,
                instance,
                schema,
                &instance_path,
                &schema_path,
                &mut children,
                &mut errors,
            )?;
            self.check_object(
                instance_document,
                instance,
                schema,
                &instance_path,
                &schema_path,
                &mut children,
                &mut errors,
            )?;
        }

        if children.is_empty() {
            results.push(Outcome { errors });
        } else {
            work.push(Task::CombineAll {
                count: children.len(),
                errors,
            });
            for child in children.into_iter().rev() {
                work.push(Task::Check {
                    schema: child.schema,
                    instance: child.instance,
                    instance_path: child.instance_path,
                    schema_path: child.schema_path,
                });
            }
        }
        Ok(())
    }

    fn check_const(
        &self,
        instance_document: &StrictJsonDocument,
        instance_id: JsonNodeId,
        schema: &[(Arc<str>, JsonNodeId)],
        instance_path: &Arc<str>,
        schema_path: &Arc<str>,
        errors: &mut Vec<ValidationError>,
    ) -> Result<(), SchemaError> {
        let Some(constant_id) = member(schema, "const") else {
            return Ok(());
        };
        if !nodes_equal(&self.schema, constant_id, instance_document, instance_id)? {
            errors.push(validation_error(
                instance_path.clone(),
                join_pointer(schema_path, "const"),
                "instance does not equal the required constant",
            ));
        }
        Ok(())
    }

    fn check_number(
        &self,
        instance: &JsonNode,
        schema: &[(Arc<str>, JsonNodeId)],
        instance_path: &Arc<str>,
        schema_path: &Arc<str>,
        errors: &mut Vec<ValidationError>,
    ) -> Result<(), SchemaError> {
        let JsonNode::Number(number) = instance else {
            return Ok(());
        };
        for (keyword, minimum) in [("minimum", true), ("maximum", false)] {
            let Some(limit_id) = member(schema, keyword) else {
                continue;
            };
            let JsonNode::Number(limit) =
                self.schema
                    .node(limit_id)
                    .ok_or_else(|| SchemaError::InvalidSchema {
                        location: join_pointer(schema_path, keyword),
                    })?
            else {
                return Err(SchemaError::InvalidSchema {
                    location: join_pointer(schema_path, keyword),
                });
            };
            let ordering = number.numeric_cmp(limit);
            if (minimum && ordering == Ordering::Less)
                || (!minimum && ordering == Ordering::Greater)
            {
                errors.push(validation_error(
                    instance_path.clone(),
                    join_pointer(schema_path, keyword),
                    if minimum {
                        "number is below the inclusive minimum"
                    } else {
                        "number is above the inclusive maximum"
                    },
                ));
            }
        }
        Ok(())
    }

    fn check_string(
        &self,
        instance: &JsonNode,
        schema: &[(Arc<str>, JsonNodeId)],
        instance_path: &Arc<str>,
        schema_path: &Arc<str>,
        errors: &mut Vec<ValidationError>,
    ) -> Result<(), SchemaError> {
        let JsonNode::String(value) = instance else {
            return Ok(());
        };
        if let Some(minimum_id) = member(schema, "minLength") {
            let minimum = schema_usize(&self.schema, minimum_id, schema_path, "minLength")?;
            if value.chars().count() < minimum {
                errors.push(validation_error(
                    instance_path.clone(),
                    join_pointer(schema_path, "minLength"),
                    "string has fewer Unicode scalars than required",
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn check_array(
        &self,
        _instance_document: &StrictJsonDocument,
        instance: &JsonNode,
        schema: &[(Arc<str>, JsonNodeId)],
        instance_path: &Arc<str>,
        schema_path: &Arc<str>,
        children: &mut Vec<CheckSpec>,
        errors: &mut Vec<ValidationError>,
    ) -> Result<(), SchemaError> {
        let JsonNode::Array(items) = instance else {
            return Ok(());
        };
        for (keyword, minimum) in [("minItems", true), ("maxItems", false)] {
            if let Some(limit_id) = member(schema, keyword) {
                let limit = schema_usize(&self.schema, limit_id, schema_path, keyword)?;
                let invalid = if minimum {
                    items.len() < limit
                } else {
                    items.len() > limit
                };
                if invalid {
                    errors.push(validation_error(
                        instance_path.clone(),
                        join_pointer(schema_path, keyword),
                        if minimum {
                            "array has fewer items than required"
                        } else {
                            "array has more items than permitted"
                        },
                    ));
                }
            }
        }

        let prefix = member(schema, "prefixItems")
            .map(|id| {
                array(&self.schema, id).ok_or_else(|| SchemaError::InvalidSchema {
                    location: join_pointer(schema_path, "prefixItems"),
                })
            })
            .transpose()?
            .unwrap_or_default();
        for (index, (item, item_schema)) in items.iter().zip(prefix.iter()).enumerate() {
            children.push(CheckSpec {
                schema: *item_schema,
                instance: *item,
                instance_path: join_pointer(instance_path, &index.to_string()),
                schema_path: join_pointer(
                    &join_pointer(schema_path, "prefixItems"),
                    &index.to_string(),
                ),
            });
        }
        if let Some(items_schema) = member(schema, "items") {
            match self.schema.node(items_schema) {
                Some(JsonNode::Bool(false)) if items.len() > prefix.len() => {
                    errors.push(validation_error(
                        instance_path.clone(),
                        join_pointer(schema_path, "items"),
                        "array contains an additional item",
                    ));
                }
                Some(JsonNode::Bool(false)) => {}
                Some(JsonNode::Object(_)) => {
                    for (index, item) in items.iter().copied().enumerate().skip(prefix.len()) {
                        children.push(CheckSpec {
                            schema: items_schema,
                            instance: item,
                            instance_path: join_pointer(instance_path, &index.to_string()),
                            schema_path: join_pointer(schema_path, "items"),
                        });
                    }
                }
                _ => {
                    return Err(SchemaError::InvalidSchema {
                        location: join_pointer(schema_path, "items"),
                    });
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn check_object(
        &self,
        _instance_document: &StrictJsonDocument,
        instance: &JsonNode,
        schema: &[(Arc<str>, JsonNodeId)],
        instance_path: &Arc<str>,
        schema_path: &Arc<str>,
        children: &mut Vec<CheckSpec>,
        errors: &mut Vec<ValidationError>,
    ) -> Result<(), SchemaError> {
        let JsonNode::Object(values) = instance else {
            return Ok(());
        };
        let properties = member(schema, "properties")
            .map(|id| {
                object(&self.schema, id).ok_or_else(|| SchemaError::InvalidSchema {
                    location: join_pointer(schema_path, "properties"),
                })
            })
            .transpose()?
            .unwrap_or_default();
        let property_map = properties
            .iter()
            .map(|(name, id)| (name.as_ref(), *id))
            .collect::<BTreeMap<_, _>>();

        let required = member(schema, "required")
            .map(|id| schema_string_set(&self.schema, id, schema_path, "required"))
            .transpose()?
            .unwrap_or_default();
        let present = values
            .iter()
            .map(|(name, _)| name.as_ref())
            .collect::<BTreeSet<_>>();
        for name in required {
            if !present.contains(name.as_ref()) {
                errors.push(validation_error(
                    instance_path.clone(),
                    join_pointer(schema_path, "required"),
                    "object omits a required property",
                ));
            }
        }

        let additional_forbidden = member(schema, "additionalProperties")
            .is_some_and(|id| matches!(self.schema.node(id), Some(JsonNode::Bool(false))));
        for (name, value) in values {
            if let Some(property_schema) = property_map.get(name.as_ref()) {
                children.push(CheckSpec {
                    schema: *property_schema,
                    instance: *value,
                    instance_path: join_pointer(instance_path, name),
                    schema_path: join_pointer(&join_pointer(schema_path, "properties"), name),
                });
            } else if additional_forbidden {
                errors.push(validation_error(
                    join_pointer(instance_path, name),
                    join_pointer(schema_path, "additionalProperties"),
                    "object contains an additional property",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct CheckSpec {
    schema: JsonNodeId,
    instance: JsonNodeId,
    instance_path: Arc<str>,
    schema_path: Arc<str>,
}

#[derive(Clone, Copy)]
enum NormalizeDocument {
    Instance,
    Schema,
}

enum NormalizeTask {
    Instance {
        schema: JsonNodeId,
        instance: JsonNodeId,
    },
    Raw {
        document: NormalizeDocument,
        node: JsonNodeId,
    },
    String(Arc<str>),
    Byte(u8),
    Null,
}

enum Task {
    Check {
        schema: JsonNodeId,
        instance: JsonNodeId,
        instance_path: Arc<str>,
        schema_path: Arc<str>,
    },
    CombineAll {
        count: usize,
        errors: Vec<ValidationError>,
    },
    CombineBranches {
        count: usize,
        exact_one: bool,
        instance_path: Arc<str>,
        schema_path: Arc<str>,
    },
}

struct Outcome {
    errors: Vec<ValidationError>,
}

fn take_outcomes(results: &mut Vec<Outcome>, count: usize) -> Result<Vec<Outcome>, SchemaError> {
    if results.len() < count {
        return Err(SchemaError::InvalidSchema {
            location: Arc::from(""),
        });
    }
    Ok(results.split_off(results.len() - count))
}

fn object(document: &StrictJsonDocument, id: JsonNodeId) -> Option<&[(Arc<str>, JsonNodeId)]> {
    match document.node(id)? {
        JsonNode::Object(values) => Some(values),
        _ => None,
    }
}

fn array(document: &StrictJsonDocument, id: JsonNodeId) -> Option<&[JsonNodeId]> {
    match document.node(id)? {
        JsonNode::Array(values) => Some(values),
        _ => None,
    }
}

fn string(document: &StrictJsonDocument, id: JsonNodeId) -> Option<&str> {
    match document.node(id)? {
        JsonNode::String(value) => Some(value),
        _ => None,
    }
}

fn member(values: &[(Arc<str>, JsonNodeId)], name: &str) -> Option<JsonNodeId> {
    values
        .iter()
        .find_map(|(candidate, id)| (candidate.as_ref() == name).then_some(*id))
}

fn type_matches(instance: &JsonNode, expected: &str) -> bool {
    match expected {
        "null" => matches!(instance, JsonNode::Null),
        "boolean" => matches!(instance, JsonNode::Bool(_)),
        "integer" => {
            matches!(instance, JsonNode::Number(number) if number.to_gantry_int().is_ok())
        }
        "number" => {
            matches!(instance, JsonNode::Number(number) if number.to_gantry_float().is_ok())
        }
        "string" => matches!(instance, JsonNode::String(_)),
        "array" => matches!(instance, JsonNode::Array(_)),
        "object" => matches!(instance, JsonNode::Object(_)),
        _ => false,
    }
}

fn nodes_equal(
    left_document: &StrictJsonDocument,
    left: JsonNodeId,
    right_document: &StrictJsonDocument,
    right: JsonNodeId,
) -> Result<bool, SchemaError> {
    let mut work = vec![(left, right)];
    while let Some((left, right)) = work.pop() {
        match (left_document.node(left), right_document.node(right)) {
            (Some(JsonNode::Null), Some(JsonNode::Null)) => {}
            (Some(JsonNode::Bool(left)), Some(JsonNode::Bool(right))) if left == right => {}
            (Some(JsonNode::String(left)), Some(JsonNode::String(right))) if left == right => {}
            (Some(JsonNode::Number(left)), Some(JsonNode::Number(right)))
                if left.numeric_cmp(right) == Ordering::Equal => {}
            (Some(JsonNode::Array(left)), Some(JsonNode::Array(right)))
                if left.len() == right.len() =>
            {
                work.extend(left.iter().copied().zip(right.iter().copied()));
            }
            (Some(JsonNode::Object(left)), Some(JsonNode::Object(right)))
                if left.len() == right.len() =>
            {
                let right = right
                    .iter()
                    .map(|(name, id)| (name.as_ref(), *id))
                    .collect::<BTreeMap<_, _>>();
                for (name, id) in left {
                    let Some(other) = right.get(name.as_ref()) else {
                        return Ok(false);
                    };
                    work.push((*id, *other));
                }
            }
            (Some(_), Some(_)) => return Ok(false),
            _ => {
                return Err(SchemaError::InvalidSchema {
                    location: Arc::from(""),
                });
            }
        }
    }
    Ok(true)
}

fn schema_usize(
    schema: &StrictJsonDocument,
    id: JsonNodeId,
    path: &str,
    keyword: &str,
) -> Result<usize, SchemaError> {
    let Some(JsonNode::Number(number)) = schema.node(id) else {
        return Err(SchemaError::InvalidSchema {
            location: join_pointer(path, keyword),
        });
    };
    let value = number
        .to_gantry_int()
        .map_err(|_| SchemaError::InvalidSchema {
            location: join_pointer(path, keyword),
        })?;
    usize::try_from(value).map_err(|_| SchemaError::InvalidSchema {
        location: join_pointer(path, keyword),
    })
}

fn schema_string_set(
    schema: &StrictJsonDocument,
    id: JsonNodeId,
    path: &str,
    keyword: &str,
) -> Result<BTreeSet<Arc<str>>, SchemaError> {
    let values = array(schema, id).ok_or_else(|| SchemaError::InvalidSchema {
        location: join_pointer(path, keyword),
    })?;
    values
        .iter()
        .map(|id| {
            string(schema, *id)
                .map(Arc::from)
                .ok_or_else(|| SchemaError::InvalidSchema {
                    location: join_pointer(path, keyword),
                })
        })
        .collect()
}

fn join_pointer(path: &str, component: &str) -> Arc<str> {
    Arc::from(format!("{path}/{}", pointer_component(component)))
}

fn pointer_component(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn decode_pointer_component(value: &str) -> Option<String> {
    let mut output = String::new();
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            output.push(character);
            continue;
        }
        match characters.next()? {
            '0' => output.push('~'),
            '1' => output.push('/'),
            _ => return None,
        }
    }
    Some(output)
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

fn validation_error(
    instance_location: Arc<str>,
    schema_location: Arc<str>,
    message: &'static str,
) -> ValidationError {
    ValidationError {
        instance_location,
        schema_location,
        message: Arc::from(message),
    }
}

#[cfg(test)]
mod tests {
    use super::SchemaValidator;
    use crate::strict_json::{JsonLimits, StrictJsonDocument};

    fn limits() -> JsonLimits {
        JsonLimits {
            maximum_bytes: 1_000_000,
            maximum_nesting_depth: 20_000,
            maximum_nodes: 100_000,
            maximum_string_scalars: 1_000_000,
            maximum_list_items: 100_000,
        }
    }

    fn document(source: &[u8]) -> StrictJsonDocument {
        StrictJsonDocument::decode(source, limits())
            .unwrap_or_else(|error| panic!("JSON fixture failed: {error:?}"))
    }

    #[test]
    fn validates_exact_numbers_tuples_options_and_closed_objects() {
        let schema = br##"{
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "type":"object",
            "properties":{
                "count":{"type":"integer","minimum":-9007199254740991,"maximum":9007199254740991},
                "pair":{"type":"array","prefixItems":[{"type":"string"},{"anyOf":[{"type":"null"},{"type":"boolean"}]}],"items":false,"minItems":2,"maxItems":2}
            },
            "required":["count","pair"],
            "additionalProperties":false
        }"##;
        let validator = SchemaValidator::compile(&schema[..], limits())
            .unwrap_or_else(|error| panic!("schema failed: {error:?}"));
        let valid = document(br#"{"count":1e0,"pair":["x",null]}"#);
        assert_eq!(validator.validate(&valid), Ok(Vec::new()));

        let invalid = document(br#"{"count":1.5,"pair":["x",true],"extra":0}"#);
        let errors = validator
            .validate(&invalid)
            .unwrap_or_else(|error| panic!("validation failed operationally: {error:?}"));
        assert!(
            errors
                .iter()
                .any(|error| error.instance_location.as_ref() == "/count")
        );
        assert!(
            errors
                .iter()
                .any(|error| error.instance_location.as_ref() == "/extra")
        );
    }

    #[test]
    fn local_refs_and_deep_recursive_values_validate_without_native_recursion() {
        let schema = br##"{
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "$defs":{"node":{"anyOf":[{"type":"null"},{"type":"array","items":{"$ref":"#/$defs/node"}}]}},
            "$ref":"#/$defs/node"
        }"##;
        let validator = SchemaValidator::compile(&schema[..], limits())
            .unwrap_or_else(|error| panic!("schema failed: {error:?}"));
        let depth = 5_000;
        let mut source = "[".repeat(depth);
        source.push_str("null");
        source.push_str(&"]".repeat(depth));
        let instance = document(source.as_bytes());
        assert_eq!(validator.validate(&instance), Ok(Vec::new()));
    }

    #[test]
    fn one_of_requires_exactly_one_matching_tagged_branch() {
        let schema = br##"{
            "oneOf":[
                {"type":"object","properties":{"variant":{"type":"string","const":"One"}},"required":["variant"],"additionalProperties":false},
                {"type":"object","properties":{"variant":{"type":"string","const":"Two"}},"required":["variant"],"additionalProperties":false}
            ]
        }"##;
        let validator = SchemaValidator::compile(&schema[..], limits())
            .unwrap_or_else(|error| panic!("schema failed: {error:?}"));
        assert_eq!(
            validator.validate(&document(br#"{"variant":"Two"}"#)),
            Ok(Vec::new())
        );
        assert!(
            !validator
                .validate(&document(br#"{"variant":"Three"}"#))
                .unwrap_or_else(|error| panic!("validation failed: {error:?}"))
                .is_empty()
        );
    }

    #[test]
    fn normalization_materializes_nested_optional_defaults_and_nulls_atomically() {
        let schema = br##"{
            "$defs":{
                "item":{
                    "type":"object",
                    "properties":{
                        "count":{"type":"integer"},
                        "empty":{"anyOf":[{"type":"null"},{"type":"boolean"}]},
                        "note":{"anyOf":[{"type":"null"},{"type":"string"}],"default":"fallback"}
                    },
                    "required":["count"],
                    "additionalProperties":false
                }
            },
            "type":"array",
            "items":{"$ref":"#/$defs/item"}
        }"##;
        let validator = SchemaValidator::compile(&schema[..], limits())
            .unwrap_or_else(|error| panic!("schema failed: {error:?}"));
        let instance = document(br#"[{"count":1e0},{"count":2,"note":null}]"#);
        let normalized = validator
            .normalize(&instance, limits())
            .unwrap_or_else(|error| panic!("normalization failed: {error:?}"));

        assert_eq!(
            normalized.bytes(),
            br#"[{"count":1,"empty":null,"note":"fallback"},{"count":2,"empty":null,"note":null}]"#
        );

        let invalid = document(br#"[{"count":"wrong"}]"#);
        assert!(matches!(
            validator.normalize(&invalid, limits()),
            Err(super::NormalizationError::Validation(errors)) if !errors.is_empty()
        ));
    }
}
