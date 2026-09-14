//! Host-domain catalog validation and generated portable vocabulary emission.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::write_atomic_if_changed;

const CATALOG_PATH: &str = "protocol/catalogs/host-domain-contracts-v1.json";
const GOLDEN_PATH: &str = "protocol/goldens/host-domain-contracts-v1.canonical.json";
const NEGATIVE_PATH: &str = "protocol/goldens/host-domain-contracts-v1.negatives.json";
const OUTPUT_PATH: &str = "crates/gantry-ir/src/generated/host_domain.rs";

const NEGATIVES: &[&str] = &[
    "incomplete-target-mappings",
    "mismatched-family-category",
    "missing-unclassified",
    "native-detail-in-portable-field",
    "unknown-family-category",
];

const EXPECTED_FAMILIES: &[(&str, &str, &[&str], &[&str])] = &[
    (
        "codec",
        "Codec",
        &[
            "decode",
            "encode",
            "malformed-input",
            "resource-limit",
            "unclassified",
        ],
        &["application", "durable", "portable"],
    ),
    (
        "console",
        "Console",
        &["closed", "interrupted", "read", "write", "unclassified"],
        &["application"],
    ),
    (
        "dns",
        "Dns",
        &["lookup", "name-not-found", "temporary", "unclassified"],
        &["application"],
    ),
    (
        "environment",
        "Environment",
        &["access-denied", "missing", "read", "write", "unclassified"],
        &["application"],
    ),
    (
        "filesystem",
        "Filesystem",
        &[
            "access-denied",
            "already-exists",
            "missing",
            "read",
            "write",
            "unclassified",
        ],
        &["application"],
    ),
    (
        "http",
        "Http",
        &["body", "protocol", "request", "response", "unclassified"],
        &["application"],
    ),
    (
        "process",
        "Process",
        &["exit", "launch", "reap", "signal", "wait", "unclassified"],
        &["application"],
    ),
    (
        "randomness",
        "Randomness",
        &["entropy-unavailable", "invalid-request", "unclassified"],
        &["application"],
    ),
    (
        "secret",
        "Secret",
        &[
            "access-denied",
            "missing",
            "provider-failure",
            "unclassified",
        ],
        &["application"],
    ),
    (
        "socket",
        "Socket",
        &["bind", "connect", "read", "write", "unclassified"],
        &["application"],
    ),
    (
        "time",
        "Time",
        &["clock-unavailable", "deadline", "sleep", "unclassified"],
        &["application"],
    ),
    (
        "tls",
        "Tls",
        &["certificate", "handshake", "protocol", "unclassified"],
        &["application"],
    ),
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    catalog: String,
    major: u64,
    minor: u64,
    schema: String,
    schema_path: String,
    specification_revision: String,
    families: Vec<Family>,
    negative_fixtures: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Family {
    wire: String,
    rust: String,
    categories: Vec<String>,
    targets: Vec<String>,
}

pub(super) fn generate(root: &Path) -> Result<bool, String> {
    let catalog = load(root)?;
    let golden = canonical(&catalog)?;
    let negatives = render_negatives(&catalog)?;
    let rust = format_rust(&render_rust(&catalog))?;
    let mut changed = false;
    for (path, contents) in [
        (GOLDEN_PATH, golden),
        (NEGATIVE_PATH, negatives),
        (OUTPUT_PATH, rust),
    ] {
        let wrote = write_atomic_if_changed(&root.join(path), contents.as_bytes())?;
        if wrote {
            println!("generated {path}");
        }
        changed |= wrote;
    }
    Ok(changed)
}

pub(super) fn check_generated(root: &Path) -> Result<(), String> {
    let catalog = load(root)?;
    check(root, GOLDEN_PATH, canonical(&catalog)?.as_bytes())?;
    check(root, NEGATIVE_PATH, render_negatives(&catalog)?.as_bytes())?;
    check(
        root,
        OUTPUT_PATH,
        format_rust(&render_rust(&catalog))?.as_bytes(),
    )
}

fn format_rust(source: &str) -> Result<String, String> {
    let mut formatter = Command::new("rustfmt")
        .arg("--emit")
        .arg("stdout")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start rustfmt for host-domain bindings: {error}"))?;
    let stdin = formatter
        .stdin
        .as_mut()
        .ok_or_else(|| "rustfmt did not provide standard input".to_owned())?;
    stdin
        .write_all(source.as_bytes())
        .map_err(|error| format!("could not write host-domain bindings to rustfmt: {error}"))?;
    let output = formatter
        .wait_with_output()
        .map_err(|error| format!("could not format host-domain bindings: {error}"))?;
    if !output.status.success() {
        return Err("rustfmt rejected generated host-domain bindings".to_owned());
    }
    String::from_utf8(output.stdout)
        .map_err(|_| "rustfmt returned non-UTF-8 host-domain bindings".to_owned())
}

fn load(root: &Path) -> Result<Catalog, String> {
    let path = root.join(CATALOG_PATH);
    let bytes =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let catalog: Catalog = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid host-domain catalog {}: {error}", path.display()))?;
    validate(root, &catalog)?;
    Ok(catalog)
}

fn validate(root: &Path, catalog: &Catalog) -> Result<(), String> {
    if catalog.catalog != "gantry.host-domain-contracts"
        || (catalog.major, catalog.minor) != (1, 0)
        || catalog.schema != "gantry.host-domain-contracts/v1"
        || catalog.schema_path != "protocol/schemas/host-domain-contracts-v1.schema.json"
    {
        return Err(
            "host-domain catalog must identify gantry.host-domain-contracts version 1.0".to_owned(),
        );
    }
    let specification = fs::read(root.join("SPEC.md"))
        .map_err(|error| format!("could not read SPEC.md: {error}"))?;
    if !root.join(&catalog.schema_path).is_file() {
        return Err("host-domain catalog schema path is missing".to_owned());
    }
    if catalog.specification_revision != format!("{:x}", Sha256::digest(specification)) {
        return Err("host-domain catalog specification revision is stale".to_owned());
    }
    if catalog
        .negative_fixtures
        .iter()
        .map(String::as_str)
        .ne(NEGATIVES.iter().copied())
    {
        return Err(
            "host-domain negative fixtures do not match the required closed set".to_owned(),
        );
    }
    if catalog.families.len() != EXPECTED_FAMILIES.len() {
        return Err("host-domain families must match the Section 29 matrix".to_owned());
    }
    for (family, (wire_name, rust_name, categories, targets)) in
        catalog.families.iter().zip(EXPECTED_FAMILIES)
    {
        if family.wire != *wire_name || family.rust != *rust_name {
            return Err("host-domain families must match the Section 29 matrix".to_owned());
        }
        if family
            .categories
            .iter()
            .map(String::as_str)
            .ne(categories.iter().copied())
        {
            return Err(format!(
                "host-domain categories for {} must match the Section 29 matrix",
                family.wire
            ));
        }
        if family
            .targets
            .iter()
            .map(String::as_str)
            .ne(targets.iter().copied())
        {
            return Err(format!(
                "host-domain targets for {} must match the Section 29 matrix",
                family.wire
            ));
        }
    }
    Ok(())
}

fn canonical(catalog: &Catalog) -> Result<String, String> {
    let mut bytes = serde_json::to_vec(catalog)
        .map_err(|error| format!("could not encode host-domain catalog: {error}"))?;
    bytes.push(b'\n');
    String::from_utf8(bytes).map_err(|_| "host-domain canonical encoding is not UTF-8".to_owned())
}

fn render_negatives(catalog: &Catalog) -> Result<String, String> {
    let mut cases = Vec::new();
    for name in NEGATIVES {
        let mut mutated = catalog.clone();
        let expected_reason = match *name {
            "incomplete-target-mappings" => {
                mutated.families[0].targets.pop();
                "host-domain targets for codec must match the Section 29 matrix"
            }
            "mismatched-family-category" => {
                mutated.families[4].categories[1] = "handshake".to_owned();
                "host-domain categories for filesystem must match the Section 29 matrix"
            }
            "missing-unclassified" => {
                mutated.families[6].categories.pop();
                "host-domain categories for process must match the Section 29 matrix"
            }
            "native-detail-in-portable-field" => {
                mutated.families[8].categories[1] = "errno-13".to_owned();
                "host-domain categories for secret must match the Section 29 matrix"
            }
            "unknown-family-category" => {
                mutated.families[11].wire = "ambient".to_owned();
                "host-domain families must match the Section 29 matrix"
            }
            _ => return Err("host-domain negative fixture is not recognized".to_owned()),
        };
        cases.push(serde_json::json!({
            "name": name,
            "expected_reason": expected_reason,
            "catalog": mutated,
        }));
    }
    let mut bytes = serde_json::to_vec(&serde_json::json!({
        "format": "gantry.host-domain-contract-negatives/v1",
        "cases": cases,
    }))
    .map_err(|error| format!("could not encode host-domain negative fixtures: {error}"))?;
    bytes.push(b'\n');
    String::from_utf8(bytes).map_err(|_| "host-domain negative fixtures are not UTF-8".to_owned())
}

fn render_rust(catalog: &Catalog) -> String {
    let categories = catalog
        .families
        .iter()
        .flat_map(|family| family.categories.iter())
        .collect::<BTreeSet<_>>();
    let mut output = String::from(
        "// @generated by `cargo run --locked -p xtask -- generate protocol`.\n// Source: protocol/catalogs/host-domain-contracts-v1.json. Do not edit manually.\n\n",
    );
    output.push_str("/// Closed host-domain target vocabulary.\n#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]\npub enum HostTarget {\n    /// The application target.\n    Application,\n    /// The durable target.\n    Durable,\n    /// The portable target.\n    Portable,\n}\n\nimpl HostTarget {\n    /// Every target in canonical wire order.\n    pub const ALL: [Self; 3] = [Self::Application, Self::Durable, Self::Portable];\n    /// Returns the exact portable spelling.\n    #[must_use]\n    pub const fn wire_name(self) -> &'static str { match self { Self::Application => \"application\", Self::Durable => \"durable\", Self::Portable => \"portable\" } }\n}\n\n");
    output.push_str("/// Closed standard host-domain family vocabulary.\n#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]\npub enum HostDomainFamily {\n");
    for family in &catalog.families {
        output.push_str(&format!(
            "    /// The `{}` family.\n    {},\n",
            family.wire, family.rust
        ));
    }
    output.push_str("}\n\nimpl HostDomainFamily {\n    /// Every family in canonical wire order.\n    pub const ALL: [Self; 12] = [");
    for family in &catalog.families {
        output.push_str(&format!("Self::{},", family.rust));
    }
    output.push_str("];\n    /// Returns the exact portable spelling.\n    #[must_use]\n    pub const fn wire_name(self) -> &'static str { match self {");
    for family in &catalog.families {
        output.push_str(&format!("Self::{} => \"{}\",", family.rust, family.wire));
    }
    output.push_str("} }\n    /// Strictly decodes one exact portable spelling.\n    #[must_use]\n    pub fn from_wire_name(value: &str) -> Option<Self> { Self::ALL.into_iter().find(|candidate| candidate.wire_name() == value) }\n    /// Returns this family's closed category matrix row.\n    #[must_use]\n    pub const fn categories(self) -> &'static [HostDomainCategory] { match self {");
    for family in &catalog.families {
        output.push_str(&format!("Self::{} => &[", family.rust));
        for category in &family.categories {
            output.push_str(&format!("HostDomainCategory::{},", pascal(category)));
        }
        output.push_str("],");
    }
    output.push_str("} }\n    /// Returns whether this family admits the category.\n    #[must_use]\n    pub fn admits(self, category: HostDomainCategory) -> bool { self.categories().contains(&category) }\n    /// Returns whether this family applies to the declared target.\n    #[must_use]\n    pub const fn applies_to(self, target: HostTarget) -> bool { match self {");
    for family in &catalog.families {
        output.push_str(&format!("Self::{} => matches!(target,", family.rust));
        for target in &family.targets {
            output.push_str(&format!("HostTarget::{} | ", pascal(target)));
        }
        output.truncate(output.len() - 3);
        output.push_str("),");
    }
    output.push_str("} }\n}\n\n/// Closed host-domain category vocabulary.\n#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]\npub enum HostDomainCategory {\n");
    for category in categories {
        output.push_str(&format!(
            "    /// The `{category}` category.\n    {},\n",
            pascal(category)
        ));
    }
    output.push_str("}\n\nimpl HostDomainCategory {\n    /// Returns the exact portable spelling.\n    #[must_use]\n    pub const fn wire_name(self) -> &'static str { match self {");
    for category in catalog
        .families
        .iter()
        .flat_map(|family| family.categories.iter())
        .collect::<BTreeSet<_>>()
    {
        output.push_str(&format!("Self::{} => \"{category}\",", pascal(category)));
    }
    output.push_str("} }\n    /// Strictly decodes one exact portable spelling.\n    #[must_use]\n    pub fn from_wire_name(value: &str) -> Option<Self> { [");
    for category in catalog
        .families
        .iter()
        .flat_map(|family| family.categories.iter())
        .collect::<BTreeSet<_>>()
    {
        output.push_str(&format!("Self::{},", pascal(category)));
    }
    output.push_str("].into_iter().find(|candidate| candidate.wire_name() == value) }\n}\n");
    output
}

fn pascal(value: &str) -> String {
    value
        .split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

fn check(root: &Path, path: &str, expected: &[u8]) -> Result<(), String> {
    let actual =
        fs::read(root.join(path)).map_err(|error| format!("could not read {path}: {error}"))?;
    if actual != expected {
        return Err(format!(
            "{path} is stale; run `cargo run --locked -p xtask -- generate protocol`"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use serde::Deserialize;

    use super::{Catalog, validate};

    #[derive(Deserialize)]
    struct NegativeFixtures {
        format: String,
        cases: Vec<NegativeFixture>,
    }

    #[derive(Deserialize)]
    struct NegativeFixture {
        name: String,
        expected_reason: String,
        catalog: Catalog,
    }

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or_else(|| panic!("xtask has a workspace parent"))
            .to_path_buf()
    }

    #[test]
    fn checked_in_negative_catalogs_are_rejected_for_their_declared_reason() {
        let fixtures: NegativeFixtures = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../protocol/goldens/host-domain-contracts-v1.negatives.json"
        )))
        .unwrap_or_else(|error| panic!("host-domain negative fixtures must decode: {error}"));
        assert_eq!(fixtures.format, "gantry.host-domain-contract-negatives/v1");
        for fixture in fixtures.cases {
            assert_eq!(
                validate(&workspace_root(), &fixture.catalog),
                Err(fixture.expected_reason),
                "negative fixture {} must be refused for its declared reason",
                fixture.name
            );
        }
    }
}
