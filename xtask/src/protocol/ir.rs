//! Canonical analyzer/runtime contract validation and generated IR metadata.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::write_atomic_if_changed;

const CATALOG_PATH: &str = "protocol/catalogs/ir-contracts-v1.json";
const GOLDEN_PATH: &str = "protocol/goldens/ir-contracts-v1.canonical.json";
const OUTPUT_PATH: &str = "crates/gantry-ir/src/generated/contracts.rs";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IrCatalog {
    analysis_fact_kinds: Vec<NamedInput>,
    artifact_kinds: Vec<ArtifactKindInput>,
    catalog: String,
    core_forms: Vec<NamedInput>,
    effects: Vec<NamedInput>,
    executable_fact_kinds: Vec<NamedInput>,
    major: u64,
    minor: u64,
    operation_site_kinds: Vec<NamedInput>,
    protocols: Vec<ProtocolInput>,
    recovery_classes: Vec<NamedInput>,
    specification_revision: String,
    task_control_site_kinds: Vec<NamedInput>,
    type_expression_kinds: Vec<NamedInput>,
    type_kinds: Vec<NamedInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactKindInput {
    protocol: String,
    requirements: Vec<String>,
    resource_code: String,
    rust: String,
    wire: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedInput {
    requirements: Vec<String>,
    rust: String,
    wire: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtocolInput {
    family: String,
    major: u64,
    minor: u64,
    requirements: Vec<String>,
}

pub(super) fn generate(root: &Path) -> Result<bool, String> {
    let catalog = load(root)?;
    let golden = serde_json::to_vec(&catalog)
        .map_err(|error| format!("could not encode IR catalog: {error}"))?;
    let mut golden = golden;
    golden.push(b'\n');
    let golden_changed = write_atomic_if_changed(&root.join(GOLDEN_PATH), &golden)?;
    if golden_changed {
        println!("generated {GOLDEN_PATH}");
    }
    let rust = render_rust(&catalog);
    let rust_changed = write_atomic_if_changed(&root.join(OUTPUT_PATH), rust.as_bytes())?;
    if rust_changed {
        println!("generated {OUTPUT_PATH}");
    }
    Ok(golden_changed || rust_changed)
}

pub(super) fn check_generated(root: &Path) -> Result<(), String> {
    let catalog = load(root)?;
    let mut golden = serde_json::to_vec(&catalog)
        .map_err(|error| format!("could not encode IR catalog: {error}"))?;
    golden.push(b'\n');
    check_file(root, GOLDEN_PATH, &golden)?;
    check_file(root, OUTPUT_PATH, render_rust(&catalog).as_bytes())
}

fn load(root: &Path) -> Result<IrCatalog, String> {
    let path = root.join(CATALOG_PATH);
    let bytes =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let catalog: IrCatalog = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid IR catalog {}: {error}", path.display()))?;
    validate(root, &catalog)?;
    Ok(catalog)
}

fn validate(root: &Path, catalog: &IrCatalog) -> Result<(), String> {
    if catalog.catalog != "gantry.ir-contracts" || (catalog.major, catalog.minor) != (1, 0) {
        return Err("IR catalog must identify gantry.ir-contracts version 1.0".to_owned());
    }
    validate_digest(&catalog.specification_revision)?;
    let specification = fs::read(root.join("SPEC.md"))
        .map_err(|error| format!("could not read SPEC.md: {error}"))?;
    if catalog.specification_revision != format!("{:x}", Sha256::digest(&specification)) {
        return Err("IR catalog specification revision is stale".to_owned());
    }
    let specification =
        String::from_utf8(specification).map_err(|_| "SPEC.md is not valid UTF-8".to_owned())?;

    validate_named(
        "artifact kind",
        catalog
            .artifact_kinds
            .iter()
            .map(|item| (&item.wire, &item.rust)),
    )?;
    validate_named(
        "analysis fact kind",
        catalog
            .analysis_fact_kinds
            .iter()
            .map(|item| (&item.wire, &item.rust)),
    )?;
    validate_named(
        "core form",
        catalog
            .core_forms
            .iter()
            .map(|item| (&item.wire, &item.rust)),
    )?;
    validate_named(
        "executable fact kind",
        catalog
            .executable_fact_kinds
            .iter()
            .map(|item| (&item.wire, &item.rust)),
    )?;
    validate_named(
        "type expression kind",
        catalog
            .type_expression_kinds
            .iter()
            .map(|item| (&item.wire, &item.rust)),
    )?;
    validate_exact_named(
        "effect",
        &catalog.effects,
        &[
            "prompt",
            "decide",
            "action(read_only)",
            "action(idempotent)",
            "action(non_idempotent)",
            "spawn",
            "join",
            "background",
            "session",
            "attempt",
        ],
    )?;
    validate_exact_named(
        "operation site kind",
        &catalog.operation_site_kinds,
        &["prompt", "decide", "action"],
    )?;
    validate_exact_named(
        "recovery class",
        &catalog.recovery_classes,
        &["read_only", "idempotent", "non_idempotent"],
    )?;
    validate_exact_named(
        "task-control site kind",
        &catalog.task_control_site_kinds,
        &["spawn", "join", "joinall", "detach"],
    )?;
    validate_exact_named(
        "type kind",
        &catalog.type_kinds,
        &[
            "Unit",
            "Bool",
            "Int",
            "Float",
            "String",
            "Declared",
            "Option",
            "Result",
            "List",
            "Tuple",
            "Decision",
            "OperationError",
        ],
    )?;

    let mut protocol_names = BTreeSet::new();
    for protocol in &catalog.protocols {
        validate_wire_name(&protocol.family)?;
        if !protocol_names.insert(protocol.family.as_str())
            || (protocol.major, protocol.minor) != (1, 0)
        {
            return Err("IR protocols must be unique published version 1.0 families".to_owned());
        }
        validate_requirements(&protocol.requirements, &specification)?;
    }
    if protocol_names != BTreeSet::from(["canonical-ir", "source-map"]) {
        return Err("IR catalog must define canonical-ir and source-map protocols".to_owned());
    }
    for item in &catalog.artifact_kinds {
        validate_requirements(&item.requirements, &specification)?;
        validate_wire_name(&item.protocol)?;
        validate_wire_name(&item.resource_code)?;
    }
    for item in catalog
        .analysis_fact_kinds
        .iter()
        .chain(&catalog.core_forms)
        .chain(&catalog.effects)
        .chain(&catalog.executable_fact_kinds)
        .chain(&catalog.operation_site_kinds)
        .chain(&catalog.recovery_classes)
        .chain(&catalog.task_control_site_kinds)
        .chain(&catalog.type_expression_kinds)
        .chain(&catalog.type_kinds)
    {
        validate_requirements(&item.requirements, &specification)?;
    }
    Ok(())
}

fn validate_named<'a>(
    kind: &str,
    values: impl Iterator<Item = (&'a String, &'a String)>,
) -> Result<(), String> {
    let mut previous = None;
    let mut rust_names = BTreeSet::new();
    let mut count = 0_usize;
    for (wire, rust) in values {
        if previous.is_some_and(|value: &str| value >= wire.as_str()) {
            return Err(format!("{kind}s must be uniquely ordered by wire name"));
        }
        validate_wire_or_type_name(wire)?;
        validate_rust_name(rust)?;
        if !rust_names.insert(rust.as_str()) {
            return Err(format!("duplicate {kind} Rust name {rust}"));
        }
        previous = Some(wire.as_str());
        count += 1;
    }
    if count == 0 {
        return Err(format!("{kind} catalog must not be empty"));
    }
    Ok(())
}

fn validate_exact_named(
    kind: &str,
    values: &[NamedInput],
    expected_wires: &[&str],
) -> Result<(), String> {
    if values
        .iter()
        .map(|value| value.wire.as_str())
        .ne(expected_wires.iter().copied())
    {
        return Err(format!("{kind}s do not match the normative v1 order"));
    }
    let mut rust_names = BTreeSet::new();
    for value in values {
        validate_wire_or_type_name(&value.wire)?;
        validate_rust_name(&value.rust)?;
        if !rust_names.insert(value.rust.as_str()) {
            return Err(format!("duplicate {kind} Rust name {}", value.rust));
        }
    }
    Ok(())
}

fn validate_requirements(values: &[String], specification: &str) -> Result<(), String> {
    if values.is_empty() || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("IR requirement links must be nonempty, unique, and ordered".to_owned());
    }
    for value in values {
        if !specification.contains(&format!("<a id=\"{value}\"></a>")) {
            return Err(format!("unknown IR requirement link {value}"));
        }
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("IR specification revision must be lowercase SHA-256".to_owned());
    }
    Ok(())
}

fn validate_wire_or_type_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'(' | b')' | b'_'))
    {
        return Err(format!("invalid IR wire name {value:?}"));
    }
    Ok(())
}

fn validate_wire_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    {
        return Err(format!("invalid IR wire name {value:?}"));
    }
    Ok(())
}

fn validate_rust_name(value: &str) -> Result<(), String> {
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_uppercase())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(format!("invalid IR Rust name {value:?}"));
    }
    Ok(())
}

fn render_rust(catalog: &IrCatalog) -> String {
    let mut output = String::from(
        "// @generated by `cargo run --locked -p xtask -- generate protocol`.\n\
// Source: protocol/catalogs/ir-contracts-v1.json. Do not edit manually.\n\n",
    );
    render_enum(
        &mut output,
        "ArtifactKind",
        "portable IR artifact",
        catalog
            .artifact_kinds
            .iter()
            .map(|item| (&item.rust, &item.wire)),
    );
    render_enum(
        &mut output,
        "AnalysisFactKind",
        "generic analysis fact",
        catalog
            .analysis_fact_kinds
            .iter()
            .map(|item| (&item.rust, &item.wire)),
    );
    render_enum(
        &mut output,
        "CoreForm",
        "desugared core form",
        catalog
            .core_forms
            .iter()
            .map(|item| (&item.rust, &item.wire)),
    );
    render_enum(
        &mut output,
        "ExecutableFactKind",
        "closed executable fact",
        catalog
            .executable_fact_kinds
            .iter()
            .map(|item| (&item.rust, &item.wire)),
    );
    render_enum(
        &mut output,
        "Effect",
        "canonical inferred effect",
        catalog.effects.iter().map(|item| (&item.rust, &item.wire)),
    );
    render_enum(
        &mut output,
        "OperationSiteKind",
        "integration-operation site kind",
        catalog
            .operation_site_kinds
            .iter()
            .map(|item| (&item.rust, &item.wire)),
    );
    render_enum(
        &mut output,
        "RecoveryClass",
        "action recovery class",
        catalog
            .recovery_classes
            .iter()
            .map(|item| (&item.rust, &item.wire)),
    );
    render_enum(
        &mut output,
        "TaskControlSiteKind",
        "task-control site kind",
        catalog
            .task_control_site_kinds
            .iter()
            .map(|item| (&item.rust, &item.wire)),
    );
    render_enum(
        &mut output,
        "TypeExpressionKind",
        "generic template type expression",
        catalog
            .type_expression_kinds
            .iter()
            .map(|item| (&item.rust, &item.wire)),
    );
    render_enum(
        &mut output,
        "TypeKind",
        "closed Gantry type kind",
        catalog
            .type_kinds
            .iter()
            .map(|item| (&item.rust, &item.wire)),
    );
    output.push_str("/// Canonical-IR protocol version.\npub const CANONICAL_IR_VERSION: (u64, u64) = (1, 0);\n\n/// Source-map protocol version.\npub const SOURCE_MAP_VERSION: (u64, u64) = (1, 0);\n");
    output
}

fn render_enum<'a>(
    output: &mut String,
    name: &str,
    description: &str,
    values: impl Iterator<Item = (&'a String, &'a String)>,
) {
    let values = values.collect::<Vec<_>>();
    output.push_str(&format!(
        "/// Closed `{name}` {description} vocabulary.\n#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]\npub enum {name} {{\n"
    ));
    for (rust, wire) in &values {
        output.push_str(&format!("    /// The `{wire}` value.\n    {rust},\n"));
    }
    output.push_str(&format!(
        "}}\n\nimpl {name} {{\n    /// Returns the exact portable spelling.\n    #[must_use]\n    pub const fn wire_name(self) -> &'static str {{\n        match self {{\n"
    ));
    for (rust, wire) in &values {
        output.push_str(&format!("            Self::{rust} => \"{wire}\",\n"));
    }
    output.push_str("        }\n    }\n}\n\n");
}

fn check_file(root: &Path, relative: &str, expected: &[u8]) -> Result<(), String> {
    let actual = fs::read(root.join(relative))
        .map_err(|error| format!("could not read {relative}: {error}"))?;
    if actual != expected {
        return Err(format!(
            "{relative} is stale; run `cargo run --locked -p xtask -- generate protocol`"
        ));
    }
    Ok(())
}
