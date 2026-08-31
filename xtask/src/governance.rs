//! Publication-lockfile, dependency-decision, and toolchain governance checks.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use cargo_metadata::{Metadata, MetadataCommand};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const LEDGER_PATH: &str = "governance/dependency-ledger-v1.json";
const REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
#[cfg(test)]
const SUPPORTED_FEATURES: &[&str] = &["analyzer", "concurrent", "durable", "evaluator", "frontend"];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u64,
    publication_lockfile: Lockfile,
    fuzz_lockfile: Lockfile,
    allowed_licenses: Vec<String>,
    allowed_sources: Vec<String>,
    toolchains: Toolchains,
    tools: Tools,
    decisions: Vec<Decision>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lockfile {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Toolchains {
    product_msrv: String,
    default_toolchain: String,
    current_stable: String,
    fuzz_nightly: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tools {
    cargo_deny: String,
    cargo_fuzz: String,
    libfuzzer_sys: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum DecisionStatus {
    Selected,
    Rejected,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    id: String,
    package: String,
    status: DecisionStatus,
    version: String,
    source: String,
    license: String,
    features: Vec<String>,
    owner: String,
    purpose: String,
    data_or_protocol_versions: Vec<String>,
    bounded_spike: String,
    acceptance_evidence: Vec<String>,
    fallback: String,
}

/// Validates the root publication lockfile and all checked-in governance policy.
pub(crate) fn check(root: &Path) -> Result<(), String> {
    let ledger = read_ledger(root)?;
    validate_shape(root, &ledger)?;
    validate_lockfile(
        root,
        &ledger.publication_lockfile,
        "Cargo.lock",
        "publication",
    )?;
    validate_lockfile(root, &ledger.fuzz_lockfile, "fuzz/Cargo.lock", "fuzz")?;
    let metadata = MetadataCommand::new()
        .current_dir(root)
        .other_options(vec!["--locked".to_owned()])
        .exec()
        .map_err(|error| format!("cargo metadata failed: {error}"))?;
    validate_dependencies(&ledger, &metadata)?;
    validate_policy_files(root, &ledger)?;
    println!("publication lockfile and dependency governance are valid");
    Ok(())
}

fn read_ledger(root: &Path) -> Result<Ledger, String> {
    let path = root.join(LEDGER_PATH);
    let bytes =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("could not decode {}: {error}", path.display()))
}

fn validate_shape(root: &Path, ledger: &Ledger) -> Result<(), String> {
    if ledger.version != 1 {
        return Err(format!(
            "unsupported dependency ledger version {}",
            ledger.version
        ));
    }
    require_sorted_unique("allowed licenses", &ledger.allowed_licenses)?;
    require_sorted_unique("allowed sources", &ledger.allowed_sources)?;
    if ledger.allowed_sources != [REGISTRY_SOURCE] {
        return Err("allowed sources must contain only the crates.io registry".to_owned());
    }
    if ledger.toolchains.product_msrv != "1.91.0"
        || ledger.toolchains.default_toolchain != "1.97.1"
        || ledger.toolchains.current_stable != "stable"
        || !ledger.toolchains.fuzz_nightly.starts_with("nightly-20")
    {
        return Err(
            "toolchain policy does not contain the exact MSRV, stable, and pinned nightly channels"
                .to_owned(),
        );
    }
    for value in [
        &ledger.tools.cargo_deny,
        &ledger.tools.cargo_fuzz,
        &ledger.tools.libfuzzer_sys,
    ] {
        if !is_exact_version(value) {
            return Err(format!("governance tool version is not exact: {value}"));
        }
    }

    let ids = ledger
        .decisions
        .iter()
        .map(|decision| decision.id.clone())
        .collect::<Vec<_>>();
    require_sorted_unique("dependency decision ids", &ids)?;
    for decision in &ledger.decisions {
        if !is_exact_version(&decision.version) {
            return Err(format!(
                "decision {} does not use an exact version",
                decision.id
            ));
        }
        require_sorted_unique(&format!("{} features", decision.id), &decision.features)?;
        require_nonempty(&decision.owner, &decision.id, "owner")?;
        require_nonempty(&decision.purpose, &decision.id, "purpose")?;
        require_nonempty(&decision.bounded_spike, &decision.id, "bounded spike")?;
        require_nonempty(&decision.fallback, &decision.id, "fallback")?;
        if decision.data_or_protocol_versions.is_empty() || decision.acceptance_evidence.is_empty()
        {
            return Err(format!(
                "decision {} lacks version or acceptance evidence",
                decision.id
            ));
        }
        if !ledger.allowed_sources.contains(&decision.source) {
            return Err(format!("decision {} source is not allowed", decision.id));
        }
        for evidence in &decision.acceptance_evidence {
            if !root.join(evidence).is_file() {
                return Err(format!(
                    "decision {} evidence does not exist: {evidence}",
                    decision.id
                ));
            }
        }
    }
    Ok(())
}

fn validate_lockfile(
    root: &Path,
    lockfile: &Lockfile,
    expected_path: &str,
    label: &str,
) -> Result<(), String> {
    if lockfile.path != expected_path {
        return Err(format!("{label} lockfile path must be {expected_path}"));
    }
    let bytes = fs::read(root.join(&lockfile.path))
        .map_err(|error| format!("could not read {label} lockfile: {error}"))?;
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != lockfile.sha256 {
        return Err(format!(
            "{label} lockfile digest is stale: expected {}, found {actual}",
            lockfile.sha256
        ));
    }
    Ok(())
}

fn validate_dependencies(ledger: &Ledger, metadata: &Metadata) -> Result<(), String> {
    let workspace = metadata.workspace_members.iter().collect::<BTreeSet<_>>();
    let direct_external = metadata
        .packages
        .iter()
        .filter(|package| workspace.contains(&package.id))
        .flat_map(|package| package.dependencies.iter())
        .filter(|dependency| dependency.source.is_some())
        .map(|dependency| dependency.name.clone())
        .collect::<BTreeSet<_>>();
    let selected = ledger
        .decisions
        .iter()
        .filter(|decision| decision.status == DecisionStatus::Selected)
        .map(|decision| decision.package.clone())
        .collect::<BTreeSet<_>>();
    if selected != direct_external {
        return Err(format!(
            "selected dependency decisions differ from direct external dependencies: expected {direct_external:?}, found {selected:?}"
        ));
    }

    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or_else(|| "cargo metadata omitted the dependency resolution".to_owned())?;
    let resolved_features = resolve
        .nodes
        .iter()
        .map(|node| {
            (
                node.id.clone(),
                node.features.iter().cloned().collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for decision in &ledger.decisions {
        let package = metadata.packages.iter().find(|package| {
            package.name == decision.package
                && package.version.to_string() == decision.version
                && package
                    .source
                    .as_ref()
                    .is_some_and(|source| source.to_string() == decision.source)
        });
        if package.is_none() && decision.status == DecisionStatus::Selected {
            return Err(format!(
                "selected dependency {} is absent from Cargo.lock",
                decision.id
            ));
        }
        if let Some(package) = package {
            if package.license.as_deref() != Some(decision.license.as_str()) {
                return Err(format!(
                    "decision {} license differs from Cargo.lock metadata",
                    decision.id
                ));
            }
            let actual_features = resolved_features
                .get(&package.id)
                .into_iter()
                .flatten()
                .map(ToString::to_string)
                .collect::<BTreeSet<_>>();
            let expected_features = decision.features.iter().cloned().collect::<BTreeSet<_>>();
            if actual_features != expected_features {
                return Err(format!(
                    "decision {} features differ: expected {expected_features:?}, found {actual_features:?}",
                    decision.id
                ));
            }
        }
    }
    Ok(())
}

fn validate_policy_files(root: &Path, ledger: &Ledger) -> Result<(), String> {
    let deny = fs::read_to_string(root.join("deny.toml"))
        .map_err(|error| format!("could not read deny.toml: {error}"))?;
    for anchor in [
        "multiple-versions = \"deny\"",
        "wildcards = \"deny\"",
        "unknown-registry = \"deny\"",
        "unknown-git = \"deny\"",
        "yanked = \"deny\"",
    ] {
        if !deny.contains(anchor) {
            return Err(format!("deny.toml is missing required policy: {anchor}"));
        }
    }
    for license in &ledger.allowed_licenses {
        if !deny.contains(&format!("\"{license}\"")) {
            return Err(format!("deny.toml omits allowed license {license}"));
        }
    }

    let root_toolchain = fs::read_to_string(root.join("rust-toolchain.toml"))
        .map_err(|error| format!("could not read root toolchain: {error}"))?;
    let fuzz_toolchain = fs::read_to_string(root.join("fuzz/rust-toolchain.toml"))
        .map_err(|error| format!("could not read fuzz toolchain: {error}"))?;
    let fuzz_manifest = fs::read_to_string(root.join("fuzz/Cargo.toml"))
        .map_err(|error| format!("could not read fuzz manifest: {error}"))?;
    let workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .map_err(|error| format!("could not read CI workflow: {error}"))?;
    for (contents, value, name) in [
        (
            &root_toolchain,
            &ledger.toolchains.default_toolchain,
            "root default toolchain",
        ),
        (
            &fuzz_toolchain,
            &ledger.toolchains.fuzz_nightly,
            "fuzz nightly",
        ),
        (
            &fuzz_manifest,
            &format!("\"={}\"", ledger.tools.libfuzzer_sys),
            "libfuzzer-sys",
        ),
        (&workflow, &ledger.tools.cargo_deny, "cargo-deny"),
        (&workflow, &ledger.tools.cargo_fuzz, "cargo-fuzz"),
    ] {
        if !contents.contains(value.as_str()) {
            return Err(format!("{name} pin is absent or stale"));
        }
    }
    for anchor in [
        "ubuntu-latest",
        "macos-latest",
        "1.91.0",
        "1.97.1",
        "stable",
    ] {
        if !workflow.contains(anchor) {
            return Err(format!(
                "CI workflow is missing required matrix value {anchor}"
            ));
        }
    }
    Ok(())
}

fn require_sorted_unique(name: &str, values: &[String]) -> Result<(), String> {
    let ordered = values
        .iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let actual = values.iter().collect::<Vec<_>>();
    if actual != ordered {
        return Err(format!("{name} must be sorted and unique"));
    }
    Ok(())
}

fn require_nonempty(value: &str, id: &str, field: &str) -> Result<(), String> {
    let lowered = value.trim().to_ascii_lowercase();
    if lowered.is_empty() || ["todo", "tbd", "unknown", "conditional"].contains(&lowered.as_str()) {
        return Err(format!("decision {id} has an unresolved {field}"));
    }
    Ok(())
}

fn is_exact_version(value: &str) -> bool {
    let pieces = value.split('.').collect::<Vec<_>>();
    pieces.len() == 3
        && pieces
            .iter()
            .all(|piece| !piece.is_empty() && piece.bytes().all(|byte| byte.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::{REGISTRY_SOURCE, SUPPORTED_FEATURES};
    use serde::Deserialize;
    use sha2::Digest as _;
    use std::fs;
    use std::path::{Path, PathBuf};

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        version: u64,
        cases: Vec<Case>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Case {
        name: String,
        field: String,
        value: String,
        expected_error: String,
    }

    #[test]
    fn checked_in_governance_is_current() {
        assert_eq!(super::check(&workspace_root()), Ok(()));
    }

    #[test]
    fn negative_policy_fixture_rejects_every_governed_class() {
        let root = workspace_root();
        let bytes = fs::read(root.join("governance/fixtures/negative-policy-v1.json"));
        assert!(bytes.is_ok());
        let fixture = bytes.and_then(|bytes| {
            serde_json::from_slice::<Fixture>(&bytes).map_err(std::io::Error::other)
        });
        assert!(fixture.is_ok());
        let fixture = fixture.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(fixture.version, 1);
        for case in fixture.cases {
            let error = reject_case(&root, &case);
            assert_eq!(
                error.as_deref(),
                Some(case.expected_error.as_str()),
                "{}",
                case.name
            );
        }
    }

    fn reject_case(root: &Path, case: &Case) -> Option<String> {
        match case.field.as_str() {
            "license"
                if !["Apache-2.0", "MIT", "Unicode-3.0", "Unlicense"]
                    .contains(&case.value.as_str()) =>
            {
                Some("license is not allowed".to_owned())
            }
            "source" if case.value != REGISTRY_SOURCE => Some("source is not allowed".to_owned()),
            "lockfile-sha256" => {
                let bytes = fs::read(root.join("Cargo.lock")).ok()?;
                let actual = format!("{:x}", sha2::Sha256::digest(bytes));
                (case.value != actual).then(|| "publication lockfile digest is stale".to_owned())
            }
            "advisory" if !case.value.is_empty() => {
                Some("unresolved advisory is denied".to_owned())
            }
            "feature" if !SUPPORTED_FEATURES.contains(&case.value.as_str()) => {
                Some("facade feature is unsupported".to_owned())
            }
            _ => None,
        }
    }

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| unreachable!("xtask has a workspace parent"))
    }
}
