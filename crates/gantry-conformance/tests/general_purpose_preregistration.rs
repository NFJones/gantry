//! Independent checks for the general-purpose preregistration boundary.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const CATALOG_PATH: &str = "protocol/catalogs/general-purpose-preregistration-v1.json";
const GOLDEN_PATH: &str = "protocol/goldens/general-purpose-preregistration-v1.canonical.json";
const SCHEMA_PATH: &str = "protocol/schemas/general-purpose-preregistration-v1.schema.json";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    catalog: String,
    major: u64,
    minor: u64,
    specification_revision: String,
    decision_record_template: Vec<String>,
    policy: Policy,
    tasks: Vec<Entry>,
    applications: Vec<Entry>,
    matrix: Matrix,
    claim_blockers: Vec<String>,
    material_change_reruns: Vec<Rerun>,
    issues: Vec<IssueContract>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    supported_platforms: Vec<String>,
    unsupported_platforms: Vec<String>,
    provider_integration: String,
    semantic_oracles: Vec<String>,
    agent_runs_per_task: u64,
    human_trials: String,
    performance_gate: String,
    quantitative_performance_thresholds: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Entry {
    id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Matrix {
    launches: Vec<String>,
    modes: Vec<String>,
    provider_evidence: Vec<String>,
    failure_cuts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct Rerun {
    material_change: String,
    rerun: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueContract {
    id: String,
    normative_owner: String,
    compatibility_owner: String,
    evidence_owner: String,
    publication_blocker: String,
    rerun: Vec<String>,
    depends_on: Vec<String>,
}

#[test]
fn preregistration_is_current_canonical_and_closed() {
    let root = workspace_root();
    let bytes = fs::read(root.join(CATALOG_PATH)).unwrap_or_else(|error| panic!("{error}"));
    let catalog: Catalog = serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"));
    let specification = fs::read(root.join("SPEC.md")).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        catalog.specification_revision,
        format!("{:x}", Sha256::digest(specification))
    );
    assert_eq!(validate(&catalog), Ok(()));
    let issue_plan =
        fs::read_to_string(root.join("docs/reference/general-purpose-refactor-issue-plan.md"))
            .unwrap_or_else(|error| panic!("{error}"));
    let expected_issues = issue_plan
        .lines()
        .filter_map(|line| line.strip_prefix("### `GNT-GP-"))
        .filter_map(|suffix| suffix.split_once('`').map(|(id, _)| id))
        .map(|suffix| format!("GNT-GP-{suffix}"))
        .filter(|issue| issue != "GNT-GP-GATE-000")
        .collect::<Vec<_>>();
    assert_eq!(
        catalog
            .issues
            .iter()
            .map(|issue| issue.id.as_str())
            .collect::<Vec<_>>(),
        expected_issues
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        fs::read(root.join(GOLDEN_PATH)).unwrap_or_else(|error| panic!("{error}")),
        canonical_json(serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}")))
    );
    let schema: serde_json::Value = read_json(&root.join(SCHEMA_PATH));
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["policy"]["additionalProperties"],
        false
    );
}

#[test]
fn preregistration_rejects_scope_and_claim_overreach() {
    let root = workspace_root();
    let catalog: Catalog = read_json(&root.join(CATALOG_PATH));

    let mut windows = catalog.clone();
    windows
        .policy
        .supported_platforms
        .push("windows".to_owned());
    assert!(validate(&windows).is_err());

    let mut provider = catalog.clone();
    provider.policy.provider_integration = "real-provider".to_owned();
    assert!(validate(&provider).is_err());

    let mut humans = catalog.clone();
    humans.policy.human_trials = "required".to_owned();
    assert!(validate(&humans).is_err());

    let mut performance = catalog;
    performance.policy.quantitative_performance_thresholds = "250ms".to_owned();
    assert!(validate(&performance).is_err());
}

#[test]
fn preregistration_rejects_incomplete_downstream_issue_contracts() {
    let root = workspace_root();
    let mut catalog: Catalog = read_json(&root.join(CATALOG_PATH));
    catalog.issues.pop();
    assert!(validate(&catalog).is_err());

    let mut catalog: Catalog = read_json(&root.join(CATALOG_PATH));
    catalog.issues[0].normative_owner.clear();
    assert!(validate(&catalog).is_err());

    let mut catalog: Catalog = read_json(&root.join(CATALOG_PATH));
    catalog.issues[0].depends_on = vec!["GNT-GP-UNKNOWN-001".to_owned()];
    assert!(validate(&catalog).is_err());

    let mut catalog: Catalog = read_json(&root.join(CATALOG_PATH));
    catalog.issues[0].depends_on = vec![catalog.issues[0].id.clone()];
    assert!(validate(&catalog).is_err());
}

fn validate(catalog: &Catalog) -> Result<(), String> {
    if catalog.catalog != "gantry.general-purpose-preregistration"
        || (catalog.major, catalog.minor) != (1, 0)
        || catalog.policy.supported_platforms != ["linux", "macos"]
        || catalog.policy.unsupported_platforms != ["windows"]
        || catalog.policy.provider_integration != "embedding-harness-mocked-hooks-only"
        || catalog.policy.semantic_oracles
            != [
                "deterministic-fakes",
                "mocked-hooks",
                "recorded-transcripts",
            ]
        || catalog.policy.agent_runs_per_task != 1
        || catalog.policy.human_trials != "deferred-until-after-implementation"
        || catalog.policy.performance_gate != "functionality-first-no-obviously-suboptimal-design"
        || catalog.policy.quantitative_performance_thresholds != "deferred"
    {
        return Err("policy differs".to_owned());
    }
    if catalog.decision_record_template.len() != 5
        || catalog.tasks.len() != 7
        || catalog.applications.len() != 7
        || catalog.issues.len() != 77
        || catalog.claim_blockers.len() != 4
        || catalog.material_change_reruns.len() != 5
        || catalog.matrix.launches != ["embedded", "standalone"]
        || catalog.matrix.modes != ["application", "durable", "portable"]
        || catalog.matrix.provider_evidence
            != ["deterministic-fake", "mocked-hook", "recorded-transcript"]
        || catalog.matrix.failure_cuts.len() != 6
    {
        return Err("catalog membership differs".to_owned());
    }
    ordered(catalog.tasks.iter().map(|entry| entry.id.as_str()))?;
    ordered(catalog.applications.iter().map(|entry| entry.id.as_str()))?;
    ordered(
        catalog
            .material_change_reruns
            .iter()
            .map(|entry| entry.material_change.as_str()),
    )?;
    if catalog
        .material_change_reruns
        .iter()
        .any(|entry| entry.rerun.is_empty())
    {
        return Err("empty rerun set".to_owned());
    }
    if catalog.issues.iter().any(|issue| {
        issue.id == "GNT-GP-GATE-000"
            || !issue.id.starts_with("GNT-GP-")
            || issue.normative_owner.is_empty()
            || issue.compatibility_owner.is_empty()
            || issue.evidence_owner.is_empty()
            || issue.publication_blocker != "general-purpose-profile"
            || issue.rerun != ["create", "debug", "explain", "modify", "security-review"]
            || issue.depends_on.is_empty()
            || issue
                .depends_on
                .iter()
                .any(|dependency| dependency == &issue.id)
    }) {
        return Err("invalid downstream issue contract".to_owned());
    }
    let known = catalog
        .issues
        .iter()
        .map(|issue| issue.id.as_str())
        .chain(std::iter::once("GNT-GP-GATE-000"))
        .collect::<std::collections::BTreeSet<_>>();
    if catalog.issues.iter().any(|issue| {
        issue
            .depends_on
            .iter()
            .any(|dependency| !known.contains(dependency.as_str()))
    }) {
        return Err("unknown downstream issue dependency".to_owned());
    }
    Ok(())
}

fn ordered<'a>(values: impl Iterator<Item = &'a str>) -> Result<(), String> {
    let values = values.collect::<Vec<_>>();
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("unordered entries".to_owned());
    }
    Ok(())
}

fn canonical_json(value: serde_json::Value) -> Vec<u8> {
    fn sort(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(sort).collect())
            }
            serde_json::Value::Object(values) => {
                let values = values
                    .into_iter()
                    .map(|(key, value)| (key, sort(value)))
                    .collect::<BTreeMap<_, _>>();
                serde_json::Value::Object(values.into_iter().collect())
            }
            value => value,
        }
    }
    let mut bytes = serde_json::to_vec(&sort(value)).unwrap_or_else(|error| panic!("{error}"));
    bytes.push(b'\n');
    bytes
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("{error}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance crate must be in the workspace"))
        .to_path_buf()
}
