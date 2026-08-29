//! Reviewed requirement coverage and exact specification inventory generation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REVIEW_PATH: &str = "protocol/requirements/reviewed-v1.json";
const EXCERPTS_PATH: &str = "protocol/requirements/section14-v1.json";
const OUTPUT_PATH: &str = "protocol/requirements/generated/requirements-v1.json";
const SPEC_PATH: &str = "SPEC.md";

const PROFILES: &[&str] = &[
    "analyzer",
    "concurrent-evaluator",
    "durable-runtime",
    "embedding",
    "evaluator",
    "frontend",
];
const ROLES: &[&str] = &["harness", "implementation", "integration"];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewFile {
    specification: String,
    specification_sha256: String,
    regions: Vec<RegionReview>,
    requirements: Vec<RequirementReview>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegionReview {
    kind: String,
    start_line: usize,
    end_line: usize,
    rationale: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequirementReview {
    id: String,
    span_start_line: usize,
    span_end_line: usize,
    anchor_line: usize,
    body_start_line: usize,
    body_end_line: usize,
    profiles: Vec<String>,
    roles: Vec<String>,
    clauses: Vec<ClauseReview>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClauseReview {
    key: String,
    start_line: usize,
    end_line: usize,
    profiles: Vec<String>,
    roles: Vec<String>,
    state: String,
    evidence: Vec<String>,
    rationale: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExcerptReviewFile {
    specification_sha256: String,
    excerpts: Vec<ExcerptReview>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExcerptReview {
    key: String,
    section: String,
    start_line: usize,
    end_line: usize,
    classification: String,
    state: String,
    evidence: Vec<String>,
}

#[derive(Debug, Serialize)]
struct GeneratedInventory {
    format: &'static str,
    specification: String,
    specification_sha256: String,
    byte_length: usize,
    line_count: usize,
    regions: Vec<GeneratedRegion>,
    requirements: Vec<GeneratedRequirement>,
    section14_excerpts: Vec<GeneratedExcerpt>,
}

#[derive(Debug, Serialize)]
struct GeneratedRegion {
    kind: String,
    start_line: usize,
    end_line: usize,
    sha256: String,
    rationale: Option<String>,
}

#[derive(Debug, Serialize)]
struct GeneratedRequirement {
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
    clauses: Vec<ClauseReview>,
}

#[derive(Debug, Serialize)]
struct GeneratedExcerpt {
    key: String,
    section: String,
    start_line: usize,
    end_line: usize,
    sha256: String,
    classification: String,
    state: String,
    evidence: Vec<String>,
}

/// Generates the exact requirement inventory from reviewed sidecars.
pub(crate) fn generate(root: &Path) -> Result<(), String> {
    let output = render(root)?;
    if write_atomic_if_changed(&root.join(OUTPUT_PATH), &output)? {
        println!("generated {OUTPUT_PATH}");
    } else {
        println!("requirement inventory is already current");
    }
    Ok(())
}

/// Checks the requirement inventory without modifying it.
pub(crate) fn check_generated(root: &Path) -> Result<(), String> {
    let expected = render(root)?;
    let path = root.join(OUTPUT_PATH);
    let actual =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if actual != expected {
        return Err(format!(
            "{OUTPUT_PATH} is stale; run `cargo run --locked -p xtask -- generate requirements`"
        ));
    }
    println!("generated requirement inventory is current");
    Ok(())
}

fn render(root: &Path) -> Result<Vec<u8>, String> {
    let spec = fs::read(root.join(SPEC_PATH))
        .map_err(|error| format!("could not read {SPEC_PATH}: {error}"))?;
    let review: ReviewFile = read_json(&root.join(REVIEW_PATH))?;
    let excerpts: ExcerptReviewFile = read_json(&root.join(EXCERPTS_PATH))?;
    let inventory = build_inventory(&spec, review, excerpts)?;
    let mut output = serde_json::to_vec_pretty(&inventory)
        .map_err(|error| format!("could not encode requirement inventory: {error}"))?;
    output.push(b'\n');
    Ok(output)
}

fn build_inventory(
    spec: &[u8],
    review: ReviewFile,
    excerpt_review: ExcerptReviewFile,
) -> Result<GeneratedInventory, String> {
    let digest = sha256(spec);
    if review.specification != SPEC_PATH {
        return Err(format!("review must identify {SPEC_PATH}"));
    }
    if review.specification_sha256 != digest || excerpt_review.specification_sha256 != digest {
        return Err("reviewed sidecars are stale for the current SPEC.md bytes".to_owned());
    }
    let text =
        std::str::from_utf8(spec).map_err(|error| format!("SPEC.md is not UTF-8: {error}"))?;
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    validate_regions(&review.regions, lines.len())?;

    let anchors = collect_anchors(&lines)?;
    if anchors.len() != review.requirements.len() {
        return Err(format!(
            "review has {} requirements but SPEC.md has {} anchors",
            review.requirements.len(),
            anchors.len()
        ));
    }

    let allowed_profiles = PROFILES.iter().copied().collect::<BTreeSet<_>>();
    let allowed_roles = ROLES.iter().copied().collect::<BTreeSet<_>>();
    let mut seen_ids = BTreeSet::new();
    let mut reviewed_normative_lines = BTreeSet::new();
    let mut generated_requirements = Vec::new();
    for requirement in review.requirements {
        if !seen_ids.insert(requirement.id.clone()) {
            return Err(format!("duplicate reviewed requirement {}", requirement.id));
        }
        let actual_line = anchors
            .get(&requirement.id)
            .ok_or_else(|| format!("review names missing anchor {}", requirement.id))?;
        if *actual_line != requirement.anchor_line {
            return Err(format!("anchor line changed for {}", requirement.id));
        }
        if requirement.span_start_line == 0
            || requirement.span_end_line < requirement.span_start_line
            || requirement.span_end_line > lines.len()
            || !(requirement.span_start_line..=requirement.span_end_line)
                .contains(&requirement.anchor_line)
            || requirement.body_start_line != requirement.anchor_line + 1
            || requirement.body_start_line == 0
            || requirement.body_end_line < requirement.body_start_line
            || requirement.body_end_line > requirement.span_end_line
        {
            return Err(format!(
                "invalid reviewed span or body range for {}",
                requirement.id
            ));
        }
        for line in requirement.span_start_line..=requirement.span_end_line {
            if !reviewed_normative_lines.insert(line) {
                return Err(format!(
                    "reviewed requirement spans overlap at {}",
                    requirement.id
                ));
            }
        }
        let span = line_slice(
            &lines,
            requirement.span_start_line,
            requirement.span_end_line,
        )?;
        let body = line_slice(
            &lines,
            requirement.body_start_line,
            requirement.body_end_line,
        )?;
        if body.trim().is_empty() {
            return Err(format!(
                "reviewed requirement {} has an empty body",
                requirement.id
            ));
        }
        if body.lines().any(|line| {
            line.starts_with("<a id=\"GNT-") || line.starts_with("## ") || line.starts_with("### ")
        }) {
            return Err(format!(
                "reviewed body for {} crosses a structural boundary",
                requirement.id
            ));
        }
        validate_sorted_set(
            "profile",
            &requirement.profiles,
            &allowed_profiles,
            &requirement.id,
        )?;
        validate_sorted_set("role", &requirement.roles, &allowed_roles, &requirement.id)?;
        validate_clauses(&requirement)?;
        if !line_in_kind(&review.regions, requirement.anchor_line, "normative") {
            return Err(format!(
                "requirement {} is outside normative regions",
                requirement.id
            ));
        }
        generated_requirements.push(GeneratedRequirement {
            id: requirement.id,
            span_start_line: requirement.span_start_line,
            span_end_line: requirement.span_end_line,
            span_sha256: sha256(span.as_bytes()),
            anchor_line: requirement.anchor_line,
            body_start_line: requirement.body_start_line,
            body_end_line: requirement.body_end_line,
            body_sha256: sha256(body.as_bytes()),
            profiles: requirement.profiles,
            roles: requirement.roles,
            clauses: requirement.clauses,
        });
    }
    if seen_ids != anchors.keys().cloned().collect::<BTreeSet<_>>() {
        return Err("reviewed requirement IDs do not exactly match SPEC.md anchors".to_owned());
    }
    let expected_normative_lines = review
        .regions
        .iter()
        .filter(|region| region.kind == "normative")
        .flat_map(|region| region.start_line..=region.end_line)
        .collect::<BTreeSet<_>>();
    if reviewed_normative_lines != expected_normative_lines {
        return Err(
            "reviewed requirement spans do not assign every normative line exactly once".to_owned(),
        );
    }

    let generated_regions = review
        .regions
        .into_iter()
        .map(|region| {
            let bytes = line_slice(&lines, region.start_line, region.end_line)?;
            Ok(GeneratedRegion {
                kind: region.kind,
                start_line: region.start_line,
                end_line: region.end_line,
                sha256: sha256(bytes.as_bytes()),
                rationale: region.rationale,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let generated_excerpts = validate_excerpts(&lines, excerpt_review.excerpts)?;

    Ok(GeneratedInventory {
        format: "gantry.requirements/v1",
        specification: SPEC_PATH.to_owned(),
        specification_sha256: digest,
        byte_length: spec.len(),
        line_count: lines.len(),
        regions: generated_regions,
        requirements: generated_requirements,
        section14_excerpts: generated_excerpts,
    })
}

fn validate_regions(regions: &[RegionReview], line_count: usize) -> Result<(), String> {
    if regions.is_empty() {
        return Err("reviewed regions must not be empty".to_owned());
    }
    let mut next_line = 1;
    for region in regions {
        if region.start_line != next_line || region.end_line < region.start_line {
            return Err(
                "reviewed regions must partition SPEC.md without gaps or overlaps".to_owned(),
            );
        }
        if region.kind != "normative" && region.kind != "excluded" {
            return Err(format!("unknown region kind {}", region.kind));
        }
        if region.kind == "excluded" && region.rationale.as_deref().is_none_or(str::is_empty) {
            return Err("excluded regions require a rationale".to_owned());
        }
        next_line = region.end_line + 1;
    }
    if next_line != line_count + 1 {
        return Err("reviewed regions do not cover the complete SPEC.md revision".to_owned());
    }
    Ok(())
}

fn collect_anchors(lines: &[&str]) -> Result<BTreeMap<String, usize>, String> {
    let mut anchors = BTreeMap::new();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let Some(id) = trimmed
            .strip_prefix("<a id=\"")
            .and_then(|rest| rest.strip_suffix("\"></a>"))
            .filter(|id| id.starts_with("GNT-"))
        else {
            continue;
        };
        if anchors.insert(id.to_owned(), index + 1).is_some() {
            return Err(format!("duplicate requirement anchor {id}"));
        }
    }
    Ok(anchors)
}

fn validate_sorted_set(
    kind: &str,
    values: &[String],
    allowed: &BTreeSet<&str>,
    requirement: &str,
) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!("{requirement} has no applicable {kind}s"));
    }
    let mut prior: Option<&str> = None;
    for value in values {
        if !allowed.contains(value.as_str()) {
            return Err(format!("{requirement} has unknown {kind} {value}"));
        }
        if prior.is_some_and(|previous| previous >= value.as_str()) {
            return Err(format!("{requirement} {kind}s must be unique and sorted"));
        }
        prior = Some(value);
    }
    Ok(())
}

fn validate_clauses(requirement: &RequirementReview) -> Result<(), String> {
    if requirement.clauses.is_empty() {
        return Err(format!("{} has no reviewed clauses", requirement.id));
    }
    let allowed_profiles = PROFILES.iter().copied().collect::<BTreeSet<_>>();
    let allowed_roles = ROLES.iter().copied().collect::<BTreeSet<_>>();
    let mut keys = BTreeSet::new();
    let mut next_line = requirement.body_start_line;
    for clause in &requirement.clauses {
        if clause.key.is_empty()
            || !clause
                .key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !keys.insert(clause.key.as_str())
        {
            return Err(format!(
                "{} has an invalid or duplicate clause key",
                requirement.id
            ));
        }
        if clause.start_line != next_line || clause.end_line < clause.start_line {
            return Err(format!(
                "{} clause ranges must partition its reviewed body",
                requirement.id
            ));
        }
        next_line = clause.end_line + 1;
        validate_sorted_set(
            "clause profile",
            &clause.profiles,
            &allowed_profiles,
            &requirement.id,
        )?;
        validate_sorted_set(
            "clause role",
            &clause.roles,
            &allowed_roles,
            &requirement.id,
        )?;
        if clause
            .profiles
            .iter()
            .any(|profile| !requirement.profiles.contains(profile))
            || clause
                .roles
                .iter()
                .any(|role| !requirement.roles.contains(role))
        {
            return Err(format!(
                "{} clause applicability exceeds its requirement applicability",
                requirement.id
            ));
        }
        if !matches!(
            clause.state.as_str(),
            "planned" | "in-progress" | "covered" | "not-applicable" | "unresolved"
        ) {
            return Err(format!("{} has unknown clause state", requirement.id));
        }
        if clause.state == "covered" && clause.evidence.is_empty() {
            return Err(format!("{} covered clause lacks evidence", requirement.id));
        }
        if matches!(clause.state.as_str(), "not-applicable" | "unresolved")
            && clause.rationale.as_deref().is_none_or(str::is_empty)
        {
            return Err(format!("{} exclusion lacks a rationale", requirement.id));
        }
    }
    if next_line != requirement.body_end_line + 1 {
        return Err(format!(
            "{} clause ranges do not cover its complete reviewed body",
            requirement.id
        ));
    }
    Ok(())
}

fn validate_excerpts(
    lines: &[&str],
    excerpts: Vec<ExcerptReview>,
) -> Result<Vec<GeneratedExcerpt>, String> {
    let section14_start = lines
        .iter()
        .position(|line| line.starts_with("## 14. "))
        .map(|index| index + 1)
        .ok_or_else(|| "SPEC.md has no Section 14 heading".to_owned())?;
    let section15_start = lines
        .iter()
        .position(|line| line.starts_with("## 15. "))
        .map(|index| index + 1)
        .ok_or_else(|| "SPEC.md has no Section 15 heading".to_owned())?;
    let mut actual_fences = Vec::new();
    let mut open = None;
    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        if !(section14_start..section15_start).contains(&line_number) || !line.starts_with("```") {
            continue;
        }
        if let Some(start) = open.take() {
            actual_fences.push((start, line_number));
        } else {
            open = Some(line_number);
        }
    }
    if open.is_some() {
        return Err("Section 14 has an unclosed code fence".to_owned());
    }
    if actual_fences.len() != excerpts.len() {
        return Err(format!(
            "review classifies {} Section 14 excerpts but SPEC.md has {}",
            excerpts.len(),
            actual_fences.len()
        ));
    }
    let mut keys = BTreeSet::new();
    let mut generated = Vec::new();
    for (excerpt, actual) in excerpts.into_iter().zip(actual_fences) {
        if !keys.insert(excerpt.key.clone()) {
            return Err(format!("duplicate Section 14 excerpt key {}", excerpt.key));
        }
        if (excerpt.start_line, excerpt.end_line) != actual {
            return Err(format!(
                "Section 14 excerpt {} moved or changed",
                excerpt.key
            ));
        }
        if !matches!(
            excerpt.classification.as_str(),
            "complete-positive" | "complete-negative" | "focused-fragment"
        ) || !matches!(excerpt.state.as_str(), "planned" | "covered")
        {
            return Err(format!(
                "invalid Section 14 classification for {}",
                excerpt.key
            ));
        }
        if excerpt.state == "covered" && excerpt.evidence.is_empty() {
            return Err(format!("covered excerpt {} lacks evidence", excerpt.key));
        }
        let bytes = line_slice(lines, excerpt.start_line, excerpt.end_line)?;
        generated.push(GeneratedExcerpt {
            key: excerpt.key,
            section: excerpt.section,
            start_line: excerpt.start_line,
            end_line: excerpt.end_line,
            sha256: sha256(bytes.as_bytes()),
            classification: excerpt.classification,
            state: excerpt.state,
            evidence: excerpt.evidence,
        });
    }
    Ok(generated)
}

fn line_in_kind(regions: &[RegionReview], line: usize, kind: &str) -> bool {
    regions
        .iter()
        .any(|region| region.kind == kind && (region.start_line..=region.end_line).contains(&line))
}

fn line_slice(lines: &[&str], start: usize, end: usize) -> Result<String, String> {
    let slice = lines
        .get(start.saturating_sub(1)..end)
        .ok_or_else(|| format!("invalid line range {start}..={end}"))?;
    Ok(slice.concat())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid JSON {}: {error}", path.display()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_atomic_if_changed(path: &Path, contents: &[u8]) -> Result<bool, String> {
    if fs::read(path).is_ok_and(|existing| existing == contents) {
        return Ok(false);
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    let temporary = temporary_path(path);
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| format!("could not create {}: {error}", temporary.display()))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        format!("could not replace {}: {error}", path.display())
    })?;
    Ok(true)
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vec<u8>, ReviewFile, ExcerptReviewFile) {
        let spec = b"## Normative\n<a id=\"GNT-1.0\"></a>\nContract.\n## 14. Examples\n```rust\nvalue\n```\n".to_vec();
        let digest = sha256(&spec);
        (
            spec,
            ReviewFile {
                specification: SPEC_PATH.to_owned(),
                specification_sha256: digest.clone(),
                regions: vec![RegionReview {
                    kind: "normative".to_owned(),
                    start_line: 1,
                    end_line: 7,
                    rationale: None,
                }],
                requirements: vec![RequirementReview {
                    id: "GNT-1.0".to_owned(),
                    span_start_line: 1,
                    span_end_line: 7,
                    anchor_line: 2,
                    body_start_line: 3,
                    body_end_line: 3,
                    profiles: vec!["frontend".to_owned()],
                    roles: vec!["implementation".to_owned()],
                    clauses: vec![ClauseReview {
                        key: "contract".to_owned(),
                        start_line: 3,
                        end_line: 3,
                        profiles: vec!["frontend".to_owned()],
                        roles: vec!["implementation".to_owned()],
                        state: "planned".to_owned(),
                        evidence: vec![],
                        rationale: None,
                    }],
                }],
            },
            ExcerptReviewFile {
                specification_sha256: digest,
                excerpts: vec![],
            },
        )
    }

    #[test]
    fn rejects_stale_review_digest() {
        let (spec, mut review, excerpts) = fixture();
        review.specification_sha256 = "0".repeat(64);
        assert!(
            matches!(build_inventory(&spec, review, excerpts), Err(message) if message.contains("stale"))
        );
    }

    #[test]
    fn rejects_region_overlap_or_gap() {
        let (spec, mut review, excerpts) = fixture();
        review.regions[0].start_line = 2;
        assert!(
            matches!(build_inventory(&spec, review, excerpts), Err(message) if message.contains("partition"))
        );
    }

    #[test]
    fn rejects_overlapping_requirement_spans() {
        let (spec, mut review, excerpts) = fixture();
        let mut duplicate = review.requirements[0].clone();
        duplicate.id = "GNT-1.1".to_owned();
        duplicate.anchor_line = 2;
        review.requirements.push(duplicate);
        assert!(build_inventory(&spec, review, excerpts).is_err());
    }

    #[test]
    fn rejects_empty_requirement_body() {
        let (spec, mut review, excerpts) = fixture();
        review.requirements[0].body_start_line = 2;
        review.requirements[0].body_end_line = 2;
        assert!(build_inventory(&spec, review, excerpts).is_err());
    }

    #[test]
    fn rejects_missing_reviewed_anchor() {
        let (spec, mut review, excerpts) = fixture();
        review.requirements[0].id = "GNT-9.9".to_owned();
        assert!(
            matches!(build_inventory(&spec, review, excerpts), Err(message) if message.contains("missing anchor"))
        );
    }

    #[test]
    fn rejects_moved_reviewed_anchor() {
        let (spec, mut review, excerpts) = fixture();
        review.requirements[0].anchor_line = 1;
        assert!(
            matches!(build_inventory(&spec, review, excerpts), Err(message) if message.contains("anchor line changed"))
        );
    }

    #[test]
    fn rejects_duplicate_specification_anchors() {
        let spec = b"<a id=\"GNT-1.0\"></a>\nOne.\n<a id=\"GNT-1.0\"></a>\nTwo.\n";
        let lines = std::str::from_utf8(spec)
            .unwrap_or_default()
            .split_inclusive('\n')
            .collect::<Vec<_>>();
        assert!(
            matches!(collect_anchors(&lines), Err(message) if message.contains("duplicate requirement anchor"))
        );
    }

    #[test]
    fn rejects_duplicate_clause_keys() {
        let (spec, mut review, excerpts) = fixture();
        let clause = review.requirements[0].clauses[0].clone();
        review.requirements[0].clauses.push(clause);
        assert!(
            matches!(build_inventory(&spec, review, excerpts), Err(message) if message.contains("duplicate clause"))
        );
    }

    #[test]
    fn rejects_unjustified_not_applicable_clause() {
        let (spec, mut review, excerpts) = fixture();
        review.requirements[0].clauses[0].state = "not-applicable".to_owned();
        assert!(
            matches!(build_inventory(&spec, review, excerpts), Err(message) if message.contains("rationale"))
        );
    }

    #[test]
    fn rejects_clause_applicability_outside_its_requirement() {
        let (spec, mut review, excerpts) = fixture();
        review.requirements[0].clauses[0].profiles = vec!["evaluator".to_owned()];
        assert!(
            matches!(build_inventory(&spec, review, excerpts), Err(message) if message.contains("exceeds its requirement applicability"))
        );
    }
}
