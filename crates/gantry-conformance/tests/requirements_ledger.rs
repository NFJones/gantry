//! Independent validation of the reviewed requirement inventory.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct Inventory {
    format: String,
    specification: String,
    specification_sha256: String,
    byte_length: usize,
    line_count: usize,
    regions: Vec<Region>,
    requirements: Vec<Requirement>,
    section14_excerpts: Vec<Excerpt>,
}

#[derive(Debug, Deserialize)]
struct Region {
    kind: String,
    start_line: usize,
    end_line: usize,
    sha256: String,
    rationale: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
    id: String,
    span_start_line: usize,
    span_end_line: usize,
    span_sha256: String,
    anchor_line: usize,
    body_start_line: usize,
    body_end_line: usize,
    body_sha256: String,
    profiles: Vec<String>,
    roles: Vec<String>,
    clauses: Vec<Clause>,
}

#[derive(Debug, Deserialize)]
struct Clause {
    key: String,
    start_line: usize,
    end_line: usize,
    profiles: Vec<String>,
    roles: Vec<String>,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
    rationale: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Excerpt {
    key: String,
    section: String,
    start_line: usize,
    end_line: usize,
    sha256: String,
    classification: String,
    state: String,
    evidence: Vec<String>,
}

#[test]
fn generated_ledger_matches_the_exact_specification_revision() {
    let root = workspace_root();
    let spec = fs::read(root.join("SPEC.md"));
    assert!(spec.is_ok());
    let spec = spec.unwrap_or_default();
    let inventory: Inventory =
        read_json(&root.join("protocol/requirements/generated/requirements-v1.json"));
    assert_eq!(inventory.format, "gantry.requirements/v1");
    assert_eq!(inventory.specification, "SPEC.md");
    assert_eq!(inventory.specification_sha256, sha256(&spec));
    assert_eq!(inventory.byte_length, spec.len());

    let text = std::str::from_utf8(&spec);
    assert!(text.is_ok());
    let lines = text
        .unwrap_or_default()
        .split_inclusive('\n')
        .collect::<Vec<_>>();
    assert_eq!(inventory.line_count, lines.len());

    let mut next_line = 1;
    for region in &inventory.regions {
        assert_eq!(region.start_line, next_line);
        assert!(matches!(region.kind.as_str(), "normative" | "excluded"));
        if region.kind == "excluded" {
            assert!(
                region
                    .rationale
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
            );
        }
        assert_eq!(
            region.sha256,
            sha256(line_slice(&lines, region.start_line, region.end_line).as_bytes())
        );
        next_line = region.end_line + 1;
    }
    assert_eq!(next_line, lines.len() + 1);
}

#[test]
fn every_anchor_and_authoring_excerpt_is_independently_accounted_for() {
    let root = workspace_root();
    let spec = fs::read_to_string(root.join("SPEC.md"));
    assert!(spec.is_ok());
    let spec = spec.unwrap_or_default();
    let lines = spec.split_inclusive('\n').collect::<Vec<_>>();
    let inventory: Inventory =
        read_json(&root.join("protocol/requirements/generated/requirements-v1.json"));

    let actual_ids = lines
        .iter()
        .filter_map(|line| {
            line.trim_end_matches(['\r', '\n'])
                .strip_prefix("<a id=\"")
                .and_then(|rest| rest.strip_suffix("\"></a>"))
                .filter(|id| id.starts_with("GNT-"))
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>();
    let reviewed_ids = inventory
        .requirements
        .iter()
        .map(|requirement| requirement.id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_ids, reviewed_ids);
    assert_eq!(actual_ids.len(), inventory.requirements.len());

    let mut clause_keys = BTreeSet::new();
    let mut normative_lines = BTreeSet::new();
    for requirement in &inventory.requirements {
        assert_eq!(
            lines[requirement.anchor_line - 1].trim_end(),
            format!("<a id=\"{}\"></a>", requirement.id)
        );
        let body = line_slice(
            &lines,
            requirement.body_start_line,
            requirement.body_end_line,
        );
        let span = line_slice(
            &lines,
            requirement.span_start_line,
            requirement.span_end_line,
        );
        assert_eq!(requirement.span_sha256, sha256(span.as_bytes()));
        for line in requirement.span_start_line..=requirement.span_end_line {
            assert!(normative_lines.insert(line));
        }
        assert!(!body.trim().is_empty());
        assert_eq!(requirement.body_sha256, sha256(body.as_bytes()));
        assert!(!requirement.profiles.is_empty());
        assert!(!requirement.roles.is_empty());
        assert!(!requirement.clauses.is_empty());
        let mut next_clause_line = requirement.body_start_line;
        for clause in &requirement.clauses {
            assert!(clause_keys.insert(format!("{}:{}", requirement.id, clause.key)));
            assert_eq!(clause.start_line, next_clause_line);
            assert!(clause.end_line >= clause.start_line);
            next_clause_line = clause.end_line + 1;
            assert!(!clause.profiles.is_empty());
            assert!(!clause.roles.is_empty());
            assert!(
                clause
                    .profiles
                    .iter()
                    .all(|profile| requirement.profiles.contains(profile))
            );
            assert!(
                clause
                    .roles
                    .iter()
                    .all(|role| requirement.roles.contains(role))
            );
            let mut reviewed_profiles = BTreeSet::new();
            for review in &clause.profile_reviews {
                assert!(clause.profiles.contains(&review.profile));
                assert!(reviewed_profiles.insert(review.profile.as_str()));
                assert!(matches!(
                    review.state.as_str(),
                    "planned" | "in-progress" | "covered" | "not-applicable" | "unresolved"
                ));
                if review.state == "covered" {
                    assert!(!review.evidence.is_empty());
                }
                if matches!(review.state.as_str(), "not-applicable" | "unresolved") {
                    assert!(
                        review
                            .rationale
                            .as_deref()
                            .is_some_and(|value| !value.is_empty())
                    );
                }
            }
            assert_eq!(
                clause
                    .profile_reviews
                    .iter()
                    .map(|review| review.profile.as_str())
                    .collect::<Vec<_>>(),
                clause
                    .profiles
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
            );
            assert_eq!(reviewed_profiles.len(), clause.profiles.len());
        }
        assert_eq!(next_clause_line, requirement.body_end_line + 1);
    }

    let expected_normative_lines = inventory
        .regions
        .iter()
        .filter(|region| region.kind == "normative")
        .flat_map(|region| region.start_line..=region.end_line)
        .collect::<BTreeSet<_>>();
    assert_eq!(normative_lines, expected_normative_lines);

    let mut fence_pairs = Vec::new();
    let mut open = None;
    let section14_start = lines
        .iter()
        .position(|line| line.starts_with("## 14. "))
        .map(|index| index + 1);
    let section15_start = lines
        .iter()
        .position(|line| line.starts_with("## 15. "))
        .map(|index| index + 1);
    assert!(section14_start.is_some());
    assert!(section15_start.is_some());
    let section14_start = section14_start.unwrap_or_default();
    let section15_start = section15_start.unwrap_or_default();
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        if (section14_start..section15_start).contains(&number) && line.starts_with("```") {
            if let Some(start) = open.take() {
                fence_pairs.push((start, number));
            } else {
                open = Some(number);
            }
        }
    }
    assert!(open.is_none());
    assert_eq!(fence_pairs.len(), inventory.section14_excerpts.len());
    let mut excerpt_keys = BTreeSet::new();
    for (excerpt, pair) in inventory.section14_excerpts.iter().zip(fence_pairs) {
        assert!(excerpt_keys.insert(excerpt.key.clone()));
        assert!(!excerpt.section.is_empty());
        assert_eq!((excerpt.start_line, excerpt.end_line), pair);
        assert_eq!(
            excerpt.sha256,
            sha256(line_slice(&lines, pair.0, pair.1).as_bytes())
        );
        assert!(matches!(
            excerpt.classification.as_str(),
            "complete-positive" | "complete-negative" | "focused-fragment"
        ));
        assert!(matches!(excerpt.state.as_str(), "planned" | "covered"));
        if excerpt.state == "covered" {
            assert!(!excerpt.evidence.is_empty());
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path);
    assert!(bytes.is_ok(), "could not read {}", path.display());
    let value =
        bytes.and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other));
    assert!(value.is_ok(), "could not decode {}", path.display());
    value.unwrap_or_else(|_| unreachable!("assertion above checks decoding"))
}

fn line_slice(lines: &[&str], start: usize, end: usize) -> String {
    lines[start - 1..end].concat()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
