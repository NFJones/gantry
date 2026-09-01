//! Publication catalog and exact-byte golden freshness validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const CATALOG_PATH: &str = "protocol/catalogs/public-formats-v1.json";
const GOLDEN_PATH: &str = "protocol/goldens/public-formats-v1.json";
const NEGATIVE_PATH: &str = "protocol/goldens/public-formats-v1.negatives.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormatCatalog {
    catalog: String,
    major: u64,
    minor: u64,
    specification_revision: String,
    formats: Vec<FormatEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormatEntry {
    format: String,
    family: String,
    encoding: String,
    magic: Option<String>,
    byte_length: String,
    sha256: String,
    schema: String,
    golden: String,
    profiles: Vec<String>,
    requirements: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldenCatalog {
    format: String,
    fixtures: Vec<GoldenEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldenEntry {
    format: String,
    fixture_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeCatalog {
    format: String,
    cases: Vec<NegativeEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeEntry {
    name: String,
    target: String,
    mutation: String,
}

pub(super) fn check_generated(root: &Path) -> Result<(), String> {
    let catalog: FormatCatalog = read_json(root, CATALOG_PATH)?;
    let golden: GoldenCatalog = read_json(root, GOLDEN_PATH)?;
    let negatives: NegativeCatalog = read_json(root, NEGATIVE_PATH)?;
    validate_catalog(root, &catalog, &golden, &negatives)?;
    println!("public protocol format catalog and goldens are current");
    Ok(())
}

fn validate_catalog(
    root: &Path,
    catalog: &FormatCatalog,
    golden: &GoldenCatalog,
    negatives: &NegativeCatalog,
) -> Result<(), String> {
    if catalog.catalog != "gantry.public-formats" || (catalog.major, catalog.minor) != (1, 0) {
        return Err(
            "public-format catalog must identify gantry.public-formats version 1.0".to_owned(),
        );
    }
    let specification = fs::read(root.join("SPEC.md"))
        .map_err(|error| format!("could not read SPEC.md: {error}"))?;
    let revision = format!("{:x}", Sha256::digest(specification));
    if catalog.specification_revision != revision {
        return Err("public-format catalog specification revision is stale".to_owned());
    }
    if golden.format != "gantry.public-format-goldens/v1" {
        return Err("public-format golden catalog has the wrong format".to_owned());
    }
    if negatives.format != "gantry.public-format-negatives/v1" {
        return Err("public-format negative catalog has the wrong format".to_owned());
    }
    if catalog.formats.is_empty() || catalog.formats.len() != golden.fixtures.len() {
        return Err("public-format catalog and golden membership differ".to_owned());
    }

    require_sorted_unique(
        catalog.formats.iter().map(|entry| entry.format.as_str()),
        "public formats",
    )?;
    require_sorted_unique(
        golden.fixtures.iter().map(|entry| entry.format.as_str()),
        "public-format goldens",
    )?;
    require_sorted_unique(
        negatives.cases.iter().map(|entry| entry.name.as_str()),
        "public-format negatives",
    )?;

    let fixtures = golden
        .fixtures
        .iter()
        .map(|entry| {
            decode_hex(&entry.fixture_hex)
                .map(|bytes| (entry.format.as_str(), bytes))
                .map_err(|error| format!("invalid golden {}: {error}", entry.format))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut referenced_schemas = BTreeSet::new();
    let known_profiles = BTreeSet::from([
        "concurrent-evaluator",
        "durable-runtime",
        "embedding",
        "evaluator",
    ]);
    for entry in &catalog.formats {
        let bytes = fixtures
            .get(entry.format.as_str())
            .ok_or_else(|| format!("missing exact-byte golden for {}", entry.format))?;
        if entry.byte_length != bytes.len().to_string() {
            return Err(format!("stale byte length for {}", entry.format));
        }
        if entry.sha256 != format!("{:x}", Sha256::digest(bytes)) {
            return Err(format!("stale SHA-256 for {}", entry.format));
        }
        if entry.golden != GOLDEN_PATH {
            return Err(format!("unexpected golden owner for {}", entry.format));
        }
        if !matches!(
            entry.family.as_str(),
            "event" | "journal" | "recovery-projection" | "value"
        ) {
            return Err(format!("unknown protocol family for {}", entry.format));
        }
        if !matches!(
            entry.encoding.as_str(),
            "canonical-binary" | "canonical-json"
        ) {
            return Err(format!("unknown encoding for {}", entry.format));
        }
        validate_encoding(entry, bytes)?;
        validate_members(&entry.profiles, &known_profiles, "profile", &entry.format)?;
        validate_requirements(root, &entry.requirements, &entry.format)?;
        let schema_path = root.join(&entry.schema);
        if !schema_path.is_file() {
            return Err(format!("missing schema {}", entry.schema));
        }
        referenced_schemas.insert(entry.schema.as_str());
    }
    let expected_schemas = BTreeSet::from([
        "protocol/schemas/canonical-transcript-v1.schema.json",
        "protocol/schemas/public-checkpoint-formats-v1.schema.json",
        "protocol/schemas/public-journal-formats-v1.schema.json",
    ]);
    if referenced_schemas != expected_schemas {
        return Err(format!(
            "public-format schema ownership differs: expected {expected_schemas:?}, found {referenced_schemas:?}"
        ));
    }
    validate_negatives(&catalog.formats, negatives)
}

fn validate_encoding(entry: &FormatEntry, bytes: &[u8]) -> Result<(), String> {
    match (entry.encoding.as_str(), entry.magic.as_deref()) {
        ("canonical-json", None) => {
            serde_json::from_slice::<serde_json::Value>(bytes)
                .map_err(|error| format!("invalid JSON golden {}: {error}", entry.format))?;
            Ok(())
        }
        ("canonical-binary", Some(magic)) if bytes.starts_with(magic.as_bytes()) => Ok(()),
        ("canonical-binary", Some(_)) => Err(format!("binary magic differs for {}", entry.format)),
        _ => Err(format!("encoding and magic disagree for {}", entry.format)),
    }
}

fn validate_members(
    values: &[String],
    known: &BTreeSet<&str>,
    kind: &str,
    format: &str,
) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!("{format} has no {kind} membership"));
    }
    require_sorted_unique(values.iter().map(String::as_str), kind)?;
    if let Some(value) = values.iter().find(|value| !known.contains(value.as_str())) {
        return Err(format!("{format} names unknown {kind} {value}"));
    }
    Ok(())
}

fn validate_requirements(root: &Path, values: &[String], format: &str) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!("{format} has no requirement links"));
    }
    require_sorted_unique(values.iter().map(String::as_str), "requirements")?;
    let specification = fs::read_to_string(root.join("SPEC.md"))
        .map_err(|error| format!("could not read SPEC.md: {error}"))?;
    for value in values {
        if !specification.contains(&format!("<a id=\"{value}\"></a>")) {
            return Err(format!("{format} names unknown requirement {value}"));
        }
    }
    Ok(())
}

fn validate_negatives(formats: &[FormatEntry], negatives: &NegativeCatalog) -> Result<(), String> {
    if negatives.cases.len() < 3 {
        return Err("public-format negative coverage is incomplete".to_owned());
    }
    let entries = formats
        .iter()
        .map(|entry| (entry.format.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut covered_schemas = BTreeSet::new();
    for case in &negatives.cases {
        let entry = entries.get(case.target.as_str()).ok_or_else(|| {
            format!(
                "negative {} names unknown target {}",
                case.name, case.target
            )
        })?;
        if !matches!(
            case.mutation.as_str(),
            "add-root-field" | "corrupt-binary-magic" | "wrong-format"
        ) {
            return Err(format!("negative {} names unknown mutation", case.name));
        }
        covered_schemas.insert(entry.schema.as_str());
    }
    if covered_schemas.len() != 3 {
        return Err("negative vectors do not cover every public-format schema owner".to_owned());
    }
    Ok(())
}

fn require_sorted_unique<'a>(
    values: impl IntoIterator<Item = &'a str>,
    label: &str,
) -> Result<(), String> {
    let mut prior = None;
    for value in values {
        if prior.is_some_and(|prior| prior >= value) {
            return Err(format!("{label} must be strictly ordered and unique"));
        }
        prior = Some(value);
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex length is odd".to_owned());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| "hex is not UTF-8".to_owned())?;
            u8::from_str_radix(pair, 16).map_err(|_| "hex contains a non-hex byte".to_owned())
        })
        .collect()
}

fn read_json<T: serde::de::DeserializeOwned>(root: &Path, relative: &str) -> Result<T, String> {
    let path = root.join(relative);
    let bytes =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid publication artifact {}: {error}", path.display()))
}
