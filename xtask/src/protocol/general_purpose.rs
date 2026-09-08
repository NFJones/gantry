//! General-purpose preregistration policy validation and canonicalization.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::write_atomic_if_changed;

const CATALOG_PATH: &str = "protocol/catalogs/general-purpose-preregistration-v1.json";
const GOLDEN_PATH: &str = "protocol/goldens/general-purpose-preregistration-v1.canonical.json";

const DECISION_FIELDS: &[&str] = &[
    "compatibility-owner",
    "evidence-owner",
    "normative-owner",
    "publication-blocker",
    "rerun-set",
];
const TASKS: &[&str] = &[
    "cancellation",
    "create",
    "debug",
    "explain",
    "modify",
    "security-review",
    "sustained-service",
];
const APPLICATIONS: &[&str] = &[
    "agent-enabled-service",
    "concurrent-tls-client",
    "durable-agent-companion",
    "filesystem-cli",
    "http-service",
    "parser-data-library",
    "subprocess-build-tool",
];
const CLAIM_BLOCKERS: &[&str] = &[
    "general-purpose-profile",
    "production-execution-strategy",
    "stable-edition",
    "stable-standard-library",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    catalog: String,
    major: u64,
    minor: u64,
    specification_revision: String,
    decision_record_template: Vec<String>,
    policy: Policy,
    tasks: Vec<Task>,
    applications: Vec<Application>,
    matrix: Matrix,
    claim_blockers: Vec<String>,
    material_change_reruns: Vec<RerunRule>,
    issues: Vec<IssueContract>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Task {
    id: String,
    intent: String,
    acceptance: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Application {
    id: String,
    mode: String,
    intent: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    launches: Vec<String>,
    modes: Vec<String>,
    provider_evidence: Vec<String>,
    failure_cuts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RerunRule {
    material_change: String,
    rerun: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

pub(super) fn generate(root: &Path) -> Result<bool, String> {
    let catalog = load(root)?;
    let golden = canonical_json(&catalog)?;
    let changed = write_atomic_if_changed(&root.join(GOLDEN_PATH), &golden)?;
    if changed {
        println!("generated {GOLDEN_PATH}");
    }
    Ok(changed)
}

pub(super) fn check_generated(root: &Path) -> Result<(), String> {
    let catalog = load(root)?;
    let expected = canonical_json(&catalog)?;
    let actual = fs::read(root.join(GOLDEN_PATH))
        .map_err(|error| format!("could not read {GOLDEN_PATH}: {error}"))?;
    if actual != expected {
        return Err(format!(
            "{GOLDEN_PATH} is stale; run `cargo run --locked -p xtask -- generate protocol`"
        ));
    }
    Ok(())
}

fn load(root: &Path) -> Result<Catalog, String> {
    let path = root.join(CATALOG_PATH);
    let bytes =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let catalog: Catalog = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "invalid preregistration catalog {}: {error}",
            path.display()
        )
    })?;
    validate(&catalog)?;
    let specification = fs::read(root.join("SPEC.md"))
        .map_err(|error| format!("could not read SPEC.md: {error}"))?;
    if catalog.specification_revision != format!("{:x}", Sha256::digest(specification)) {
        return Err("general-purpose preregistration specification revision is stale".to_owned());
    }
    Ok(catalog)
}

fn validate(catalog: &Catalog) -> Result<(), String> {
    if catalog.catalog != "gantry.general-purpose-preregistration"
        || (catalog.major, catalog.minor) != (1, 0)
    {
        return Err("general-purpose preregistration must identify version 1.0".to_owned());
    }
    exact(
        &catalog.decision_record_template,
        DECISION_FIELDS,
        "decision fields",
    )?;
    exact(
        &catalog.policy.supported_platforms,
        &["linux", "macos"],
        "supported platforms",
    )?;
    exact(
        &catalog.policy.unsupported_platforms,
        &["windows"],
        "unsupported platforms",
    )?;
    if catalog.policy.provider_integration != "embedding-harness-mocked-hooks-only"
        || catalog.policy.agent_runs_per_task != 1
        || catalog.policy.human_trials != "deferred-until-after-implementation"
        || catalog.policy.performance_gate != "functionality-first-no-obviously-suboptimal-design"
        || catalog.policy.quantitative_performance_thresholds != "deferred"
    {
        return Err(
            "general-purpose product policy differs from the preregistered scope".to_owned(),
        );
    }
    exact(
        &catalog.policy.semantic_oracles,
        &[
            "deterministic-fakes",
            "mocked-hooks",
            "recorded-transcripts",
        ],
        "semantic oracles",
    )?;
    exact_ids(&catalog.tasks, TASKS, |task| &task.id, "tasks")?;
    if catalog
        .tasks
        .iter()
        .any(|task| task.intent.is_empty() || task.acceptance.is_empty())
    {
        return Err("every task needs fixed intent and acceptance".to_owned());
    }
    exact_ids(
        &catalog.applications,
        APPLICATIONS,
        |application| &application.id,
        "applications",
    )?;
    if catalog.applications.iter().any(|application| {
        application.intent.is_empty()
            || !matches!(
                application.mode.as_str(),
                "application" | "durable" | "portable"
            )
    }) {
        return Err("every application needs a valid mode and fixed intent".to_owned());
    }
    exact(
        &catalog.matrix.launches,
        &["embedded", "standalone"],
        "launches",
    )?;
    exact(
        &catalog.matrix.modes,
        &["application", "durable", "portable"],
        "modes",
    )?;
    exact(
        &catalog.matrix.provider_evidence,
        &["deterministic-fake", "mocked-hook", "recorded-transcript"],
        "provider evidence",
    )?;
    exact(
        &catalog.matrix.failure_cuts,
        &[
            "after-acceptance",
            "after-effect-before-commit",
            "after-result-commit",
            "before-admission",
            "during-cancellation",
            "during-cleanup",
        ],
        "failure cuts",
    )?;
    exact(&catalog.claim_blockers, CLAIM_BLOCKERS, "claim blockers")?;
    validate_reruns(&catalog.material_change_reruns)?;
    validate_issue_contracts(&catalog.issues)
}

fn validate_reruns(rules: &[RerunRule]) -> Result<(), String> {
    let expected = ["api", "diagnostics", "documentation", "strategy", "syntax"];
    exact_ids(
        rules,
        &expected,
        |rule| &rule.material_change,
        "rerun rules",
    )?;
    for rule in rules {
        if rule.rerun.is_empty() {
            return Err(format!("{} has no rerun set", rule.material_change));
        }
        ordered_unique(&rule.rerun, "rerun set")?;
    }
    Ok(())
}

fn validate_issue_contracts(issues: &[IssueContract]) -> Result<(), String> {
    if issues.len() != 77 {
        return Err("all 77 downstream issues need preregistration contracts".to_owned());
    }
    let mut ids = BTreeSet::new();
    for issue in issues {
        if issue.id == "GNT-GP-GATE-000"
            || !issue.id.starts_with("GNT-GP-")
            || !ids.insert(issue.id.as_str())
            || issue.normative_owner.is_empty()
            || issue.compatibility_owner.is_empty()
            || issue.evidence_owner.is_empty()
            || issue.publication_blocker != "general-purpose-profile"
        {
            return Err(format!("invalid downstream issue contract: {}", issue.id));
        }
        exact(
            &issue.rerun,
            &["create", "debug", "explain", "modify", "security-review"],
            "downstream issue rerun set",
        )?;
        ordered_unique(&issue.depends_on, "downstream issue dependencies")?;
        if issue.depends_on.is_empty()
            || issue
                .depends_on
                .iter()
                .any(|dependency| dependency == &issue.id)
        {
            return Err(format!(
                "invalid downstream issue dependencies: {}",
                issue.id
            ));
        }
    }
    let known = ids
        .iter()
        .copied()
        .chain(std::iter::once("GNT-GP-GATE-000"))
        .collect::<BTreeSet<_>>();
    for issue in issues {
        if let Some(dependency) = issue
            .depends_on
            .iter()
            .find(|dependency| !known.contains(dependency.as_str()))
        {
            return Err(format!(
                "{} names unknown dependency {dependency}",
                issue.id
            ));
        }
    }
    reject_issue_cycles(issues)
}

fn reject_issue_cycles(issues: &[IssueContract]) -> Result<(), String> {
    fn visit<'a>(
        id: &'a str,
        issues: &BTreeMap<&'a str, &'a IssueContract>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> Result<(), String> {
        if id == "GNT-GP-GATE-000" || visited.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id) {
            return Err(format!(
                "general-purpose issue dependency cycle includes {id}"
            ));
        }
        for dependency in &issues[id].depends_on {
            visit(dependency, issues, visiting, visited)?;
        }
        visiting.remove(id);
        visited.insert(id);
        Ok(())
    }

    let issues = issues
        .iter()
        .map(|issue| (issue.id.as_str(), issue))
        .collect::<BTreeMap<_, _>>();
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in issues.keys().copied() {
        visit(id, &issues, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn exact(values: &[String], expected: &[&str], label: &str) -> Result<(), String> {
    if values
        .iter()
        .map(String::as_str)
        .ne(expected.iter().copied())
    {
        return Err(format!("{label} differ from the preregistered set"));
    }
    Ok(())
}

fn exact_ids<T>(
    values: &[T],
    expected: &[&str],
    id: impl Fn(&T) -> &String,
    label: &str,
) -> Result<(), String> {
    if values
        .iter()
        .map(|value| id(value).as_str())
        .ne(expected.iter().copied())
    {
        return Err(format!("{label} differ from the preregistered set"));
    }
    Ok(())
}

fn ordered_unique(values: &[String], label: &str) -> Result<(), String> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!("{label} must be strictly ordered and unique"));
    }
    Ok(())
}

fn canonical_json(catalog: &Catalog) -> Result<Vec<u8>, String> {
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
    let value = serde_json::to_value(catalog)
        .map_err(|error| format!("could not encode preregistration catalog: {error}"))?;
    let mut bytes = serde_json::to_vec(&sort(value))
        .map_err(|error| format!("could not canonicalize preregistration catalog: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{Catalog, validate};

    fn fixture_catalog() -> Catalog {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../protocol/catalogs/general-purpose-preregistration-v1.json"
        )))
        .unwrap_or_else(|error| panic!("test catalog must decode: {error}"))
    }

    #[test]
    fn checked_in_policy_is_valid() {
        assert_eq!(validate(&fixture_catalog()), Ok(()));
    }

    #[test]
    fn policy_rejects_real_providers_humans_and_performance_thresholds() {
        let mut catalog = fixture_catalog();
        catalog.policy.provider_integration = "real-provider-smoke".to_owned();
        assert!(validate(&catalog).is_err());

        let mut catalog = fixture_catalog();
        catalog.policy.human_trials = "required".to_owned();
        assert!(validate(&catalog).is_err());

        let mut catalog = fixture_catalog();
        catalog.policy.quantitative_performance_thresholds = "latency-250ms".to_owned();
        assert!(validate(&catalog).is_err());
    }
}
