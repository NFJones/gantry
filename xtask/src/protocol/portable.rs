//! Portable catalog validation and generated Rust bindings.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::write_atomic_if_changed;

const CATALOG_PATH: &str = "protocol/catalogs/portable-contracts-v1.json";
const GOLDEN_PATH: &str = "protocol/goldens/portable-contracts-v1.canonical.json";
const OUTPUT_PATH: &str = "crates/gantry-core/src/generated/portable.rs";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PortableCatalog {
    catalog: String,
    major: u64,
    minor: u64,
    specification_revision: String,
    maximum_directive_integer: String,
    identity_kinds: Vec<IdentityKindInput>,
    protocol_families: Vec<ProtocolFamilyInput>,
    vocabularies: Vec<VocabularyInput>,
    events: Vec<EventInput>,
    configuration_fields: Vec<ConfigurationFieldInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityKindInput {
    wire: String,
    rust: String,
    origin: String,
    requirements: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedInput {
    wire: String,
    rust: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    requirements: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtocolFamilyInput {
    wire: String,
    rust: String,
    major: u64,
    minor: u64,
    requirements: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VocabularyInput {
    name: String,
    rust: String,
    values: Vec<NamedInput>,
    requirements: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EventInput {
    wire: String,
    rust: String,
    layer: String,
    requirements: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationFieldInput {
    wire: String,
    rust: String,
    class: String,
    default: Option<String>,
    zero_allowed: Option<bool>,
    maximum: Option<String>,
    requirements: Vec<String>,
}

pub(super) fn generate(root: &Path) -> Result<bool, String> {
    let catalog = load_catalog(root)?;
    let golden = canonical_json(&catalog)?;
    let golden_changed = write_atomic_if_changed(&root.join(GOLDEN_PATH), golden.as_slice())?;
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
    let expected_golden = canonical_json(&catalog)?;
    let golden_path = root.join(GOLDEN_PATH);
    let actual_golden = fs::read(&golden_path)
        .map_err(|error| format!("could not read {}: {error}", golden_path.display()))?;
    if actual_golden != expected_golden {
        return Err(format!(
            "{GOLDEN_PATH} is stale; run `cargo run --locked -p xtask -- generate protocol`"
        ));
    }
    let expected = render_rust(&catalog);
    let path = root.join(OUTPUT_PATH);
    let actual =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if actual != expected.as_bytes() {
        return Err(format!(
            "{OUTPUT_PATH} is stale; run `cargo run --locked -p xtask -- generate protocol`"
        ));
    }
    Ok(())
}

fn load_catalog(root: &Path) -> Result<PortableCatalog, String> {
    let path = root.join(CATALOG_PATH);
    let bytes =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let catalog: PortableCatalog = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid portable catalog {}: {error}", path.display()))?;
    validate(&catalog)?;
    let specification_path = root.join("SPEC.md");
    let specification = fs::read(&specification_path)
        .map_err(|error| format!("could not read {}: {error}", specification_path.display()))?;
    let revision = format!("{:x}", Sha256::digest(&specification));
    if catalog.specification_revision != revision {
        return Err("portable catalog specification revision is stale".to_owned());
    }
    let specification =
        String::from_utf8(specification).map_err(|_| "SPEC.md is not valid UTF-8".to_owned())?;
    for requirement in requirement_links(&catalog) {
        let anchor = format!("<a id=\"{requirement}\"></a>");
        if !specification.contains(&anchor) {
            return Err(format!(
                "unknown portable-catalog requirement link {requirement}"
            ));
        }
    }
    Ok(catalog)
}

fn validate(catalog: &PortableCatalog) -> Result<(), String> {
    if catalog.catalog != "gantry.portable-contracts" || (catalog.major, catalog.minor) != (1, 0) {
        return Err(
            "portable catalog must identify gantry.portable-contracts version 1.0".to_owned(),
        );
    }
    if catalog.specification_revision.len() != 64
        || !catalog
            .specification_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("portable catalog specification revision must be lowercase SHA-256".to_owned());
    }
    validate_decimal(&catalog.maximum_directive_integer)?;
    if catalog.maximum_directive_integer != "9223372036854775807" {
        return Err("portable catalog has the wrong v1 directive integer maximum".to_owned());
    }
    validate_named_list(
        "identity kind",
        catalog
            .identity_kinds
            .iter()
            .map(|item| (item.wire.as_str(), item.rust.as_str())),
    )?;
    for kind in &catalog.identity_kinds {
        validate_requirements(&kind.requirements)?;
        if !matches!(
            kind.origin.as_str(),
            "fresh" | "derived" | "fresh-or-derived" | "storage"
        ) {
            return Err(format!("unknown identity origin {}", kind.origin));
        }
    }
    validate_named_list(
        "protocol family",
        catalog
            .protocol_families
            .iter()
            .map(|item| (item.wire.as_str(), item.rust.as_str())),
    )?;
    for family in &catalog.protocol_families {
        validate_requirements(&family.requirements)?;
        if (family.major, family.minor) != (1, 0) {
            return Err(format!(
                "unsupported v1 protocol version {}.{} for {}",
                family.major, family.minor, family.wire
            ));
        }
    }

    let mut vocabulary_names = BTreeSet::new();
    let mut vocabulary_rust_names = BTreeSet::new();
    for vocabulary in &catalog.vocabularies {
        validate_wire_name(&vocabulary.name)?;
        validate_rust_name(&vocabulary.rust)?;
        validate_requirements(&vocabulary.requirements)?;
        if !vocabulary_names.insert(vocabulary.name.as_str())
            || !vocabulary_rust_names.insert(vocabulary.rust.as_str())
        {
            return Err(format!("duplicate vocabulary {}", vocabulary.name));
        }
        if vocabulary.values.is_empty() {
            return Err(format!("vocabulary {} is empty", vocabulary.name));
        }
        validate_named_list(
            &format!("{} value", vocabulary.name),
            vocabulary
                .values
                .iter()
                .map(|item| (item.wire.as_str(), item.rust.as_str())),
        )?;
    }

    validate_named_list(
        "event",
        catalog
            .events
            .iter()
            .map(|item| (item.wire.as_str(), item.rust.as_str())),
    )?;
    for event in &catalog.events {
        validate_requirements(&event.requirements)?;
        if !matches!(event.layer.as_str(), "logical" | "physical") {
            return Err(format!("unknown event layer {}", event.layer));
        }
    }

    validate_named_list(
        "configuration field",
        catalog
            .configuration_fields
            .iter()
            .map(|item| (item.wire.as_str(), item.rust.as_str())),
    )?;
    for field in &catalog.configuration_fields {
        validate_requirements(&field.requirements)?;
        if !matches!(
            field.class.as_str(),
            "activity-policy"
                | "durably-mutable"
                | "identity-bound"
                | "integration-owned"
                | "scheduling-only"
        ) {
            return Err(format!("unknown configuration class {}", field.class));
        }
        for value in [field.default.as_deref(), field.maximum.as_deref()]
            .into_iter()
            .flatten()
            .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        {
            validate_decimal(value)?;
        }
    }
    Ok(())
}

fn validate_named_list<'a>(
    kind: &str,
    values: impl Iterator<Item = (&'a str, &'a str)>,
) -> Result<(), String> {
    let mut prior: Option<&str> = None;
    let mut wire_names = BTreeSet::new();
    let mut rust_names = BTreeSet::new();
    for (wire, rust) in values {
        validate_wire_name(wire)?;
        validate_rust_name(rust)?;
        if prior.is_some_and(|value| value >= wire) {
            return Err(format!("{kind}s must be unique and ordered by wire name"));
        }
        prior = Some(wire);
        if !wire_names.insert(wire) || !rust_names.insert(rust) {
            return Err(format!("duplicate {kind} {wire}"));
        }
    }
    Ok(())
}

fn validate_wire_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-' || byte == b'_')
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

fn validate_decimal(value: &str) -> Result<(), String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("invalid canonical unsigned decimal {value:?}"));
    }
    Ok(())
}

fn validate_requirements(requirements: &[String]) -> Result<(), String> {
    if requirements.is_empty() {
        return Err("portable catalog entries must link at least one requirement".to_owned());
    }
    let mut prior: Option<&str> = None;
    for requirement in requirements {
        if !requirement.starts_with("GNT-")
            || !requirement
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        {
            return Err(format!("invalid requirement link {requirement:?}"));
        }
        if prior.is_some_and(|value| value >= requirement.as_str()) {
            return Err("requirement links must be unique and ordered".to_owned());
        }
        prior = Some(requirement);
    }
    Ok(())
}

fn requirement_links(catalog: &PortableCatalog) -> impl Iterator<Item = &str> {
    catalog
        .identity_kinds
        .iter()
        .flat_map(|item| item.requirements.iter())
        .chain(
            catalog
                .protocol_families
                .iter()
                .flat_map(|item| item.requirements.iter()),
        )
        .chain(
            catalog
                .vocabularies
                .iter()
                .flat_map(|item| item.requirements.iter()),
        )
        .chain(
            catalog
                .events
                .iter()
                .flat_map(|item| item.requirements.iter()),
        )
        .chain(
            catalog
                .configuration_fields
                .iter()
                .flat_map(|item| item.requirements.iter()),
        )
        .map(String::as_str)
}

fn canonical_json(catalog: &PortableCatalog) -> Result<Vec<u8>, String> {
    fn sort(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(sort).collect())
            }
            serde_json::Value::Object(values) => {
                let sorted = values
                    .into_iter()
                    .map(|(key, value)| (key, sort(value)))
                    .collect::<std::collections::BTreeMap<_, _>>();
                serde_json::Value::Object(sorted.into_iter().collect())
            }
            other => other,
        }
    }

    let value = serde_json::to_value(catalog)
        .map_err(|error| format!("could not encode portable catalog: {error}"))?;
    let mut output = serde_json::to_vec(&sort(value))
        .map_err(|error| format!("could not canonicalize portable catalog: {error}"))?;
    output.push(b'\n');
    Ok(output)
}

fn render_rust(catalog: &PortableCatalog) -> String {
    let mut output = String::from(
        "// @generated by `cargo run --locked -p xtask -- generate protocol`.\n\
// Source: protocol/catalogs/portable-contracts-v1.json. Do not edit manually.\n\n",
    );
    output.push_str(&format!(
        "/// SHA-256 of the exact reviewed `SPEC.md` revision.\npub const PORTABLE_SPECIFICATION_REVISION: &str = \"{}\";\n\n",
        catalog.specification_revision
    ));
    render_enum_with_wire(
        &mut output,
        "IdentityOrigin",
        &[
            ("derived", "Derived"),
            ("fresh", "Fresh"),
            ("fresh-or-derived", "FreshOrDerived"),
            ("storage", "Storage"),
        ],
    );
    render_enum_with_wire(
        &mut output,
        "IdentityKind",
        &catalog
            .identity_kinds
            .iter()
            .map(|item| (item.wire.as_str(), item.rust.as_str()))
            .collect::<Vec<_>>(),
    );
    output.push_str("\n/// All occurrence identity kinds in canonical wire-name order.\npub const IDENTITY_KINDS: &[IdentityKind] = &[\n");
    for item in &catalog.identity_kinds {
        output.push_str(&format!("    IdentityKind::{},\n", item.rust));
    }
    output.push_str("];\n");
    output.push_str("\nimpl IdentityKind {\n    /// Returns how values of this kind originate.\n    #[must_use]\n    pub const fn origin(self) -> IdentityOrigin {\n        match self {\n");
    for item in &catalog.identity_kinds {
        output.push_str(&format!(
            "            Self::{} => IdentityOrigin::{},\n",
            item.rust,
            rust_variant(&item.origin)
        ));
    }
    output.push_str("        }\n    }\n}\n");
    render_enum_with_wire(
        &mut output,
        "ProtocolFamily",
        &catalog
            .protocol_families
            .iter()
            .map(|item| (item.wire.as_str(), item.rust.as_str()))
            .collect::<Vec<_>>(),
    );
    output.push_str("\n/// All protocol families in canonical wire-name order.\npub const PROTOCOL_FAMILIES: &[ProtocolFamily] = &[\n");
    for item in &catalog.protocol_families {
        output.push_str(&format!("    ProtocolFamily::{},\n", item.rust));
    }
    output.push_str("];\n");
    output.push_str("\n/// Exact published version for one protocol family.\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct ProtocolFamilyDefinition {\n    /// Protocol family.\n    pub family: ProtocolFamily,\n    /// Published major version.\n    pub major: u64,\n    /// Published minor version.\n    pub minor: u64,\n}\n\n/// Exact protocol-family versions in canonical family order.\npub const PROTOCOL_FAMILY_DEFINITIONS: &[ProtocolFamilyDefinition] = &[\n");
    for item in &catalog.protocol_families {
        output.push_str(&format!(
            "    ProtocolFamilyDefinition {{ family: ProtocolFamily::{}, major: {}, minor: {} }},\n",
            item.rust, item.major, item.minor
        ));
    }
    output.push_str("];\n");

    for vocabulary in &catalog.vocabularies {
        render_enum_with_wire(
            &mut output,
            &vocabulary.rust,
            &vocabulary
                .values
                .iter()
                .map(|item| (item.wire.as_str(), item.rust.as_str()))
                .collect::<Vec<_>>(),
        );
    }
    output.push_str("\n/// Generic metadata for one closed portable vocabulary.\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct PortableVocabularyDefinition {\n    /// Canonical vocabulary name.\n    pub name: &'static str,\n    /// Canonically ordered wire values.\n    pub values: &'static [&'static str],\n}\n\n/// All closed portable vocabularies in canonical name order.\npub const PORTABLE_VOCABULARIES: &[PortableVocabularyDefinition] = &[\n");
    for vocabulary in &catalog.vocabularies {
        let values = vocabulary
            .values
            .iter()
            .map(|item| format!("\"{}\"", item.wire))
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!(
            "    PortableVocabularyDefinition {{ name: \"{}\", values: &[{}] }},\n",
            vocabulary.name, values
        ));
    }
    output.push_str("];\n");

    render_enum_with_wire(
        &mut output,
        "EventLayer",
        &[("logical", "Logical"), ("physical", "Physical")],
    );
    render_enum_with_wire(
        &mut output,
        "EventKind",
        &catalog
            .events
            .iter()
            .map(|item| (item.wire.as_str(), item.rust.as_str()))
            .collect::<Vec<_>>(),
    );
    output.push_str("\nimpl EventKind {\n    /// Returns the exact required observation layer.\n    #[must_use]\n    pub const fn layer(self) -> EventLayer {\n        match self {\n");
    for event in &catalog.events {
        output.push_str(&format!(
            "            Self::{} => EventLayer::{},\n",
            event.rust,
            rust_variant(&event.layer)
        ));
    }
    output.push_str("        }\n    }\n}\n");
    output.push_str("\n/// Metadata for one standard event kind.\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct EventKindDefinition {\n    /// Event kind.\n    pub kind: EventKind,\n    /// Required observation layer.\n    pub layer: EventLayer,\n}\n\n/// All event kinds in canonical wire-name order.\npub const EVENT_KINDS: &[EventKindDefinition] = &[\n");
    for event in &catalog.events {
        output.push_str(&format!(
            "    EventKindDefinition {{ kind: EventKind::{}, layer: EventLayer::{} }},\n",
            event.rust,
            rust_variant(&event.layer)
        ));
    }
    output.push_str("];\n");

    render_enum_with_wire(
        &mut output,
        "ConfigurationClass",
        &[
            ("activity-policy", "ActivityPolicy"),
            ("durably-mutable", "DurablyMutable"),
            ("identity-bound", "IdentityBound"),
            ("integration-owned", "IntegrationOwned"),
            ("scheduling-only", "SchedulingOnly"),
        ],
    );
    render_enum_with_wire(
        &mut output,
        "ConfigurationField",
        &catalog
            .configuration_fields
            .iter()
            .map(|item| (item.wire.as_str(), item.rust.as_str()))
            .collect::<Vec<_>>(),
    );
    output.push_str("\n/// Metadata for one configuration field.\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct ConfigurationFieldDefinition {\n    /// Field identity.\n    pub field: ConfigurationField,\n    /// Compatibility class.\n    pub class: ConfigurationClass,\n    /// Canonical default when one is normative.\n    pub default: Option<&'static str>,\n    /// Whether numeric zero is accepted, or `None` for nonnumeric fields.\n    pub zero_allowed: Option<bool>,\n    /// Inclusive canonical decimal maximum when applicable.\n    pub maximum: Option<&'static str>,\n}\n\n/// All configuration fields in canonical wire-name order.\npub const CONFIGURATION_FIELDS: &[ConfigurationFieldDefinition] = &[\n");
    for field in &catalog.configuration_fields {
        output.push_str(&format!(
            "    ConfigurationFieldDefinition {{ field: ConfigurationField::{}, class: ConfigurationClass::{}, default: {}, zero_allowed: {}, maximum: {} }},\n",
            field.rust,
            rust_variant(&field.class),
            option_literal(field.default.as_deref()),
            field
                .zero_allowed
                .map_or_else(|| "None".to_owned(), |value| format!("Some({value})")),
            option_literal(field.maximum.as_deref())
        ));
    }
    output.push_str(&format!(
        "];\n\n/// Fixed Gantry v1 directive integer maximum.\npub const MAXIMUM_DIRECTIVE_INTEGER: u64 = {};\n",
        catalog.maximum_directive_integer
    ));
    output
}

fn render_enum_with_wire(output: &mut String, name: &str, values: &[(&str, &str)]) {
    output.push_str(&format!(
        "\n/// Closed `{}` portable vocabulary.\n#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]\npub enum {name} {{\n",
        name
    ));
    for (wire, rust) in values {
        output.push_str(&format!("    /// The `{wire}` value.\n    {rust},\n"));
    }
    output.push_str(&format!(
        "}}\n\nimpl {name} {{\n    /// Returns the exact portable spelling.\n    #[must_use]\n    pub const fn wire_name(self) -> &'static str {{\n        match self {{\n"
    ));
    for (wire, rust) in values {
        output.push_str(&format!("            Self::{rust} => \"{wire}\",\n"));
    }
    output.push_str("        }\n    }\n\n    /// Parses one exact portable spelling.\n    #[must_use]\n    pub fn from_wire_name(value: &str) -> Option<Self> {\n        match value {\n");
    for (wire, rust) in values {
        output.push_str(&format!("            \"{wire}\" => Some(Self::{rust}),\n"));
    }
    output.push_str("            _ => None,\n        }\n    }\n}\n");
}

fn rust_variant(value: &str) -> String {
    value
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            match characters.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + characters.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

fn option_literal(value: Option<&str>) -> String {
    value.map_or_else(|| "None".to_owned(), |value| format!("Some(\"{value}\")"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_and_unsorted_wire_values() {
        let values = [("beta", "Beta"), ("alpha", "Alpha")];
        assert!(validate_named_list("fixture", values.into_iter()).is_err());
    }

    #[test]
    fn rejects_noncanonical_decimal_metadata() {
        assert!(validate_decimal("01").is_err());
        assert!(validate_decimal("-1").is_err());
        assert_eq!(validate_decimal("0"), Ok(()));
    }

    #[test]
    fn rejects_missing_duplicate_and_invalid_requirement_links() {
        assert!(validate_requirements(&[]).is_err());
        assert!(validate_requirements(&["GNT-15.8".to_owned(), "GNT-15.8".to_owned()]).is_err());
        assert!(validate_requirements(&["not-a-requirement".to_owned()]).is_err());
        assert_eq!(validate_requirements(&["GNT-15.8".to_owned()]), Ok(()));
    }
}
