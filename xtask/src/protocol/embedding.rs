//! Embedding contract validation and generated host metadata.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::write_atomic_if_changed;

const CATALOG_PATH: &str = "protocol/catalogs/embedding-contracts-v1.json";
const GOLDEN_PATH: &str = "protocol/goldens/embedding-contracts-v1.canonical.json";
const OUTPUT_PATH: &str = "crates/gantry-host/src/generated/embedding.rs";

const SERVICES: &[&str] = &[
    "blocking",
    "event",
    "executor",
    "hook",
    "identity",
    "journal",
    "lifecycle",
    "preflight",
    "session",
];
const ROLES: &[&str] = &[
    "blocking-work-service",
    "event-sink",
    "executor-adapter",
    "hook-factory",
    "identity-source",
    "integration-preflight",
    "interpreter",
    "journal-storage",
    "operation-hook",
    "runtime-session-service",
];
const PROFILES: &[&str] = &[
    "analyzer",
    "concurrent-evaluator",
    "durable-runtime",
    "embedding",
    "evaluator",
    "frontend",
];
const ASYNC_KINDS: &[&str] = &[
    "borrowed-future",
    "owned-blocking-job",
    "owned-task-future",
    "synchronous",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingCatalog {
    analysis_result_fields: Vec<AnalysisResultFieldInput>,
    catalog: String,
    major: u64,
    minor: u64,
    specification_revision: String,
    operations: Vec<OperationInput>,
    failure_matrix: Vec<FailureInput>,
    trait_bounds: Vec<TraitBoundInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AnalysisResultFieldInput {
    wire: String,
    requirements: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationInput {
    wire: String,
    rust: String,
    service: String,
    role: String,
    applicable_profiles: Vec<String>,
    request_fields: Vec<String>,
    optional_request_fields: Vec<String>,
    result_variants: Vec<String>,
    error_categories: Vec<String>,
    acceptance: String,
    idempotency: String,
    cancellation: String,
    async_kind: String,
    requirements: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FailureInput {
    origin: String,
    boundary: String,
    mapping: String,
    poison_scope: String,
    requirements: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TraitBoundInput {
    role: String,
    send: bool,
    sync: bool,
    returned_future: String,
    requirements: Vec<String>,
}

pub(super) fn generate(root: &Path) -> Result<bool, String> {
    let catalog = load_catalog(root)?;
    let golden = canonical_json(&catalog)?;
    let golden_changed = write_atomic_if_changed(&root.join(GOLDEN_PATH), &golden)?;
    if golden_changed {
        println!("generated {GOLDEN_PATH}");
    }
    let output = render_rust(&catalog);
    let output_changed = write_atomic_if_changed(&root.join(OUTPUT_PATH), output.as_bytes())?;
    if output_changed {
        println!("generated {OUTPUT_PATH}");
    }
    Ok(golden_changed || output_changed)
}

pub(super) fn check_generated(root: &Path) -> Result<(), String> {
    let catalog = load_catalog(root)?;
    check_file(root, GOLDEN_PATH, &canonical_json(&catalog)?)?;
    check_file(root, OUTPUT_PATH, render_rust(&catalog).as_bytes())
}

fn check_file(root: &Path, relative: &str, expected: &[u8]) -> Result<(), String> {
    let path = root.join(relative);
    let actual =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if actual != expected {
        return Err(format!(
            "{relative} is stale; run `cargo run --locked -p xtask -- generate protocol`"
        ));
    }
    Ok(())
}

fn load_catalog(root: &Path) -> Result<EmbeddingCatalog, String> {
    let path = root.join(CATALOG_PATH);
    let bytes =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let catalog: EmbeddingCatalog = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid embedding catalog {}: {error}", path.display()))?;
    validate(&catalog)?;

    let specification_path = root.join("SPEC.md");
    let specification = fs::read(&specification_path)
        .map_err(|error| format!("could not read {}: {error}", specification_path.display()))?;
    if catalog.specification_revision != format!("{:x}", Sha256::digest(&specification)) {
        return Err("embedding catalog specification revision is stale".to_owned());
    }
    let specification =
        String::from_utf8(specification).map_err(|_| "SPEC.md is not valid UTF-8".to_owned())?;
    for requirement in requirement_links(&catalog) {
        let anchor = format!("<a id=\"{requirement}\"></a>");
        if !specification.contains(&anchor) {
            return Err(format!("unknown embedding requirement link {requirement}"));
        }
    }
    Ok(catalog)
}

fn validate(catalog: &EmbeddingCatalog) -> Result<(), String> {
    if catalog.catalog != "gantry.embedding-contracts" || (catalog.major, catalog.minor) != (1, 0) {
        return Err(
            "embedding catalog must identify gantry.embedding-contracts version 1.0".to_owned(),
        );
    }
    validate_digest(&catalog.specification_revision)?;
    validate_analysis_result_fields(&catalog.analysis_result_fields)?;
    validate_operations(&catalog.operations)?;
    validate_failure_matrix(&catalog.failure_matrix)?;
    validate_trait_bounds(&catalog.trait_bounds)
}

fn validate_analysis_result_fields(entries: &[AnalysisResultFieldInput]) -> Result<(), String> {
    if entries.is_empty() {
        return Err("analysis result field catalog must not be empty".to_owned());
    }
    let mut prior: Option<&str> = None;
    for entry in entries {
        validate_wire_name(&entry.wire)?;
        if prior.is_some_and(|value| value >= entry.wire.as_str()) {
            return Err("analysis result fields must be unique and ordered".to_owned());
        }
        prior = Some(&entry.wire);
        validate_requirements(&entry.requirements)?;
    }
    Ok(())
}

fn validate_operations(operations: &[OperationInput]) -> Result<(), String> {
    if operations.is_empty() {
        return Err("embedding operation catalog must not be empty".to_owned());
    }
    let mut prior: Option<&str> = None;
    let mut wires = BTreeSet::new();
    let mut rust_names = BTreeSet::new();
    for operation in operations {
        validate_wire_name(&operation.wire)?;
        validate_rust_name(&operation.rust)?;
        if prior.is_some_and(|value| value >= operation.wire.as_str()) {
            return Err("embedding operations must be uniquely ordered by wire name".to_owned());
        }
        prior = Some(&operation.wire);
        if !wires.insert(operation.wire.as_str()) || !rust_names.insert(operation.rust.as_str()) {
            return Err(format!("duplicate embedding operation {}", operation.wire));
        }
        validate_member(&operation.service, SERVICES, "service")?;
        validate_member(&operation.role, ROLES, "role")?;
        validate_member(&operation.async_kind, ASYNC_KINDS, "async kind")?;
        validate_string_list(&operation.applicable_profiles, "applicable profile", true)?;
        for profile in &operation.applicable_profiles {
            validate_member(profile, PROFILES, "profile")?;
        }
        validate_string_list(&operation.request_fields, "request field", false)?;
        validate_string_list(
            &operation.optional_request_fields,
            "optional request field",
            false,
        )?;
        if operation
            .request_fields
            .iter()
            .any(|field| operation.optional_request_fields.contains(field))
        {
            return Err(format!(
                "operation {} repeats a required field as optional",
                operation.wire
            ));
        }
        validate_string_list(&operation.result_variants, "result variant", true)?;
        validate_string_list(&operation.error_categories, "error category", false)?;
        validate_wire_name(&operation.acceptance)?;
        validate_wire_name(&operation.idempotency)?;
        validate_wire_name(&operation.cancellation)?;
        validate_requirements(&operation.requirements)?;
    }
    Ok(())
}

fn validate_failure_matrix(entries: &[FailureInput]) -> Result<(), String> {
    if entries.is_empty() {
        return Err("failure matrix must not be empty".to_owned());
    }
    let mut keys = BTreeSet::new();
    for entry in entries {
        for value in [
            &entry.origin,
            &entry.boundary,
            &entry.mapping,
            &entry.poison_scope,
        ] {
            validate_wire_name(value)?;
        }
        if !keys.insert((entry.origin.as_str(), entry.boundary.as_str())) {
            return Err(format!(
                "duplicate failure boundary {}/{}",
                entry.origin, entry.boundary
            ));
        }
        validate_requirements(&entry.requirements)?;
    }
    Ok(())
}

fn validate_trait_bounds(entries: &[TraitBoundInput]) -> Result<(), String> {
    let mut prior: Option<&str> = None;
    let mut roles = BTreeSet::new();
    for entry in entries {
        validate_member(&entry.role, ROLES, "trait role")?;
        if prior.is_some_and(|value| value >= entry.role.as_str())
            || !roles.insert(entry.role.as_str())
        {
            return Err("trait bounds must be uniquely ordered by role".to_owned());
        }
        prior = Some(&entry.role);
        validate_member(
            &entry.returned_future,
            &["send-borrowed", "synchronous"],
            "returned future",
        )?;
        validate_requirements(&entry.requirements)?;
    }
    Ok(())
}

fn validate_string_list(values: &[String], kind: &str, required: bool) -> Result<(), String> {
    if required && values.is_empty() {
        return Err(format!("{kind} list must not be empty"));
    }
    let mut prior: Option<&str> = None;
    for value in values {
        validate_wire_name(value)?;
        if prior.is_some_and(|item| item >= value.as_str()) {
            return Err(format!("{kind}s must be unique and ordered"));
        }
        prior = Some(value);
    }
    Ok(())
}

fn validate_requirements(values: &[String]) -> Result<(), String> {
    if values.is_empty() {
        return Err("requirement links must not be empty".to_owned());
    }
    let mut prior: Option<&str> = None;
    for value in values {
        if !value.starts_with("GNT-")
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        {
            return Err(format!("invalid requirement link {value:?}"));
        }
        if prior.is_some_and(|item| item >= value.as_str()) {
            return Err("requirement links must be unique and ordered".to_owned());
        }
        prior = Some(value);
    }
    Ok(())
}

fn validate_member(value: &str, allowed: &[&str], kind: &str) -> Result<(), String> {
    if !allowed.contains(&value) {
        return Err(format!("unknown {kind} {value:?}"));
    }
    Ok(())
}

fn validate_wire_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.starts_with(['-', '_'])
        || value.ends_with(['-', '_'])
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(format!("invalid wire name {value:?}"));
    }
    Ok(())
}

fn validate_rust_name(value: &str) -> Result<(), String> {
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_uppercase())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(format!("invalid Rust name {value:?}"));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("specification revision must be lowercase SHA-256".to_owned());
    }
    Ok(())
}

fn requirement_links(catalog: &EmbeddingCatalog) -> impl Iterator<Item = &str> {
    catalog
        .analysis_result_fields
        .iter()
        .flat_map(|entry| entry.requirements.iter())
        .chain(
            catalog
                .operations
                .iter()
                .flat_map(|entry| entry.requirements.iter()),
        )
        .chain(
            catalog
                .failure_matrix
                .iter()
                .flat_map(|entry| entry.requirements.iter()),
        )
        .chain(
            catalog
                .trait_bounds
                .iter()
                .flat_map(|entry| entry.requirements.iter()),
        )
        .map(String::as_str)
}

fn canonical_json(catalog: &EmbeddingCatalog) -> Result<Vec<u8>, String> {
    fn sort(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(sort).collect())
            }
            serde_json::Value::Object(values) => {
                let sorted = values
                    .into_iter()
                    .map(|(key, value)| (key, sort(value)))
                    .collect::<BTreeMap<_, _>>();
                serde_json::Value::Object(sorted.into_iter().collect())
            }
            other => other,
        }
    }

    let value = serde_json::to_value(catalog)
        .map_err(|error| format!("could not encode embedding catalog: {error}"))?;
    let mut output = serde_json::to_vec(&sort(value))
        .map_err(|error| format!("could not canonicalize embedding catalog: {error}"))?;
    output.push(b'\n');
    Ok(output)
}

fn render_rust(catalog: &EmbeddingCatalog) -> String {
    let mut output = String::from(
        "// @generated by `cargo run --locked -p xtask -- generate protocol`.\n\
// Source: protocol/catalogs/embedding-contracts-v1.json. Do not edit manually.\n\n",
    );
    output.push_str(&format!(
        "/// SHA-256 of the reviewed specification revision.\npub const EMBEDDING_SPECIFICATION_REVISION: &str = \"{}\";\n",
        catalog.specification_revision
    ));
    output.push_str("\n/// Structured fields returned by successful semantic analysis.\npub const ANALYSIS_RESULT_FIELDS: &[&str] = &[\n");
    for field in &catalog.analysis_result_fields {
        output.push_str(&format!("    \"{}\",\n", field.wire));
    }
    output.push_str("];\n");
    render_enum(
        &mut output,
        "EmbeddingOperation",
        &catalog
            .operations
            .iter()
            .map(|entry| (entry.wire.as_str(), entry.rust.clone()))
            .collect::<Vec<_>>(),
    );
    render_enum(
        &mut output,
        "HostService",
        &SERVICES
            .iter()
            .map(|wire| (*wire, rust_variant(wire)))
            .collect::<Vec<_>>(),
    );
    render_enum(
        &mut output,
        "IntegrationRole",
        &ROLES
            .iter()
            .map(|wire| (*wire, rust_variant(wire)))
            .collect::<Vec<_>>(),
    );
    render_enum(
        &mut output,
        "OperationAsyncKind",
        &ASYNC_KINDS
            .iter()
            .map(|wire| (*wire, rust_variant(wire)))
            .collect::<Vec<_>>(),
    );
    render_enum(
        &mut output,
        "FailureOrigin",
        &unique_values(
            catalog
                .failure_matrix
                .iter()
                .map(|entry| entry.origin.as_str()),
        ),
    );
    render_enum(
        &mut output,
        "FailureBoundary",
        &unique_values(
            catalog
                .failure_matrix
                .iter()
                .map(|entry| entry.boundary.as_str()),
        ),
    );
    render_enum(
        &mut output,
        "FailureMapping",
        &unique_values(
            catalog
                .failure_matrix
                .iter()
                .map(|entry| entry.mapping.as_str()),
        ),
    );
    render_enum(
        &mut output,
        "PoisonScope",
        &unique_values(
            catalog
                .failure_matrix
                .iter()
                .map(|entry| entry.poison_scope.as_str()),
        ),
    );
    render_enum(
        &mut output,
        "ReturnedFutureKind",
        &unique_values(
            catalog
                .trait_bounds
                .iter()
                .map(|entry| entry.returned_future.as_str()),
        ),
    );

    output.push_str(
        "\n/// Canonical contract metadata for one embedding operation.\n\
#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
pub struct EmbeddingOperationDefinition {\n\
    /// Operation identity.\n    pub operation: EmbeddingOperation,\n\
    /// Owning host service.\n    pub service: HostService,\n\
    /// Integration role.\n    pub role: IntegrationRole,\n\
    /// Applicable conformance profiles.\n    pub applicable_profiles: &'static [&'static str],\n\
    /// Required request fields.\n    pub request_fields: &'static [&'static str],\n\
    /// Optional request fields.\n    pub optional_request_fields: &'static [&'static str],\n\
    /// Closed result variants.\n    pub result_variants: &'static [&'static str],\n\
    /// Closed error categories.\n    pub error_categories: &'static [&'static str],\n\
    /// Acceptance boundary.\n    pub acceptance: &'static str,\n\
    /// Idempotency contract.\n    pub idempotency: &'static str,\n\
    /// Cancellation contract.\n    pub cancellation: &'static str,\n\
    /// Async ownership shape.\n    pub async_kind: OperationAsyncKind,\n\
}\n\n/// All embedding operations in canonical wire-name order.\n\
pub const EMBEDDING_OPERATIONS: &[EmbeddingOperationDefinition] = &[\n",
    );
    for entry in &catalog.operations {
        output.push_str(&format!(
            "    EmbeddingOperationDefinition {{ operation: EmbeddingOperation::{}, service: HostService::{}, role: IntegrationRole::{}, applicable_profiles: &{}, request_fields: &{}, optional_request_fields: &{}, result_variants: &{}, error_categories: &{}, acceptance: \"{}\", idempotency: \"{}\", cancellation: \"{}\", async_kind: OperationAsyncKind::{} }},\n",
            entry.rust,
            rust_variant(&entry.service),
            rust_variant(&entry.role),
            string_slice(&entry.applicable_profiles),
            string_slice(&entry.request_fields),
            string_slice(&entry.optional_request_fields),
            string_slice(&entry.result_variants),
            string_slice(&entry.error_categories),
            entry.acceptance,
            entry.idempotency,
            entry.cancellation,
            rust_variant(&entry.async_kind),
        ));
    }
    output.push_str("];\n");

    output.push_str(
        "\n/// One origin-preserving failure-boundary rule.\n\
#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
pub struct FailureBoundaryDefinition {\n\
    /// Failure origin.\n    pub origin: FailureOrigin,\n\
    /// Boundary that observes the failure.\n    pub boundary: FailureBoundary,\n\
    /// Required portable mapping.\n    pub mapping: FailureMapping,\n\
    /// Required poison scope.\n    pub poison_scope: PoisonScope,\n\
}\n\n/// Complete v1 boundary-failure matrix.\n\
pub const FAILURE_BOUNDARIES: &[FailureBoundaryDefinition] = &[\n",
    );
    for entry in &catalog.failure_matrix {
        output.push_str(&format!(
            "    FailureBoundaryDefinition {{ origin: FailureOrigin::{}, boundary: FailureBoundary::{}, mapping: FailureMapping::{}, poison_scope: PoisonScope::{} }},\n",
            rust_variant(&entry.origin),
            rust_variant(&entry.boundary),
            rust_variant(&entry.mapping),
            rust_variant(&entry.poison_scope),
        ));
    }
    output.push_str("];\n");

    output.push_str(
        "\n/// Rust auto-trait and future ownership requirements for one role.\n\
#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
pub struct TraitBoundDefinition {\n\
    /// Integration role.\n    pub role: IntegrationRole,\n\
    /// Whether implementations must be `Send`.\n    pub send: bool,\n\
    /// Whether implementations must be `Sync`.\n    pub sync: bool,\n\
    /// Returned future requirement.\n    pub returned_future: ReturnedFutureKind,\n\
}\n\n/// Complete v1 integration-role trait bounds.\n\
pub const TRAIT_BOUNDS: &[TraitBoundDefinition] = &[\n",
    );
    for entry in &catalog.trait_bounds {
        output.push_str(&format!(
            "    TraitBoundDefinition {{ role: IntegrationRole::{}, send: {}, sync: {}, returned_future: ReturnedFutureKind::{} }},\n",
            rust_variant(&entry.role), entry.send, entry.sync, rust_variant(&entry.returned_future),
        ));
    }
    output.push_str("];\n");
    output
}

fn render_enum(output: &mut String, name: &str, values: &[(&str, String)]) {
    output.push_str(&format!(
        "\n/// Closed `{name}` protocol vocabulary.\n#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]\npub enum {name} {{\n"
    ));
    for (wire, rust) in values {
        output.push_str(&format!("    /// The `{wire}` value.\n    {rust},\n"));
    }
    output.push_str(&format!(
        "}}\n\nimpl {name} {{\n    /// Returns the exact protocol spelling.\n    #[must_use]\n    pub const fn wire_name(self) -> &'static str {{\n        match self {{\n"
    ));
    for (wire, rust) in values {
        output.push_str(&format!("            Self::{rust} => \"{wire}\",\n"));
    }
    output.push_str("        }\n    }\n\n    /// Parses one exact protocol spelling.\n    #[must_use]\n    pub fn from_wire_name(value: &str) -> Option<Self> {\n        match value {\n");
    for (wire, rust) in values {
        output.push_str(&format!("            \"{wire}\" => Some(Self::{rust}),\n"));
    }
    output.push_str("            _ => None,\n        }\n    }\n}\n");
}

fn unique_values<'a>(values: impl Iterator<Item = &'a str>) -> Vec<(&'a str, String)> {
    values
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|wire| (wire, rust_variant(wire)))
        .collect()
}

fn rust_variant(value: &str) -> String {
    value
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_ascii_uppercase().to_string() + characters.as_str()
            })
        })
        .collect()
}

fn string_slice(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::{validate_digest, validate_string_list, validate_wire_name};

    #[test]
    fn rejects_noncanonical_names_and_lists() {
        assert!(validate_wire_name("Unknown").is_err());
        assert!(validate_string_list(&["z".to_owned(), "a".to_owned()], "fixture", true).is_err());
        assert!(validate_string_list(&[], "fixture", true).is_err());
    }

    #[test]
    fn rejects_noncanonical_specification_digests() {
        assert!(validate_digest(&"AB".repeat(32)).is_err());
        assert!(validate_digest("ab").is_err());
        assert_eq!(validate_digest(&"ab".repeat(32)), Ok(()));
    }
}
