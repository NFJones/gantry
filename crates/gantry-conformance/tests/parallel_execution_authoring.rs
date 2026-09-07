//! Public-facade checks for the parallel-execution source-author guide.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::analysis::{AnalysisStatus, analyze_package_types};
use gantry::frontend::validate_package_syntax;
use gantry::runtime::InstructionKind;
use gantry::source::SourceLimits;
use serde::Deserialize;

const ISSUE: &str = "GNT-ASYNC-DOC-001";

#[derive(Debug, Deserialize)]
struct Contract {
    requirement_assignments: Vec<RequirementAssignment>,
}

#[derive(Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct RequirementAssignment {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
    evidence_owners: Vec<String>,
}

#[test]
fn hook_free_parallel_example_analyzes_and_lowers_task_ownership() {
    let root = workspace_root();
    let example = root.join("examples/parallel-execution");
    let syntax = validate_package_syntax(
        &example,
        SourceLimits::new(8, 1_048_576, 4_194_304, 262_144, 256)
            .unwrap_or_else(|_| unreachable!("positive example limits")),
        256,
    )
    .unwrap_or_else(|error| panic!("parallel example syntax failed: {error}"));
    let package = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("parallel example analysis failed: {error:?}"));
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );

    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("parallel example omitted its entry"));
    let program = package
        .executable_program()
        .unwrap_or_else(|| panic!("parallel example omitted executable lowering"));
    let workflow = program
        .workflow(&entry.path)
        .unwrap_or_else(|| panic!("parallel example entry was not lowered"));

    let controls = workflow
        .instructions
        .iter()
        .filter_map(|instruction| match &instruction.kind {
            InstructionKind::Spawn { handle, .. } => Some(format!("spawn:{}", handle.name())),
            InstructionKind::Join { handles } => Some(format!(
                "join:{}",
                handles
                    .iter()
                    .map(AsRef::as_ref)
                    .collect::<Vec<_>>()
                    .join(",")
            )),
            InstructionKind::JoinAll { handles } => Some(format!(
                "joinall:{}",
                handles
                    .iter()
                    .map(AsRef::as_ref)
                    .collect::<Vec<_>>()
                    .join(",")
            )),
            InstructionKind::Detach { handle } => Some(format!("detach:{handle}")),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        controls,
        [
            "spawn:incremented",
            "join:incremented",
            "spawn:label",
            "spawn:marker",
            "joinall:label,marker",
            "spawn:audit",
            "detach:audit",
        ]
    );

    let captures = program
        .task_bodies()
        .iter()
        .map(|body| {
            (
                body.result_type().canonical_string(),
                body.captures()
                    .iter()
                    .map(|capture| (capture.name(), capture.is_mutable()))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(captures.len(), 4);
    assert!(
        captures.iter().any(|(result, captures)| {
            result == "Int" && captures.as_slice() == [("seed", true)]
        })
    );
    assert_eq!(workflow.result.canonical_string(), "crate::ParallelResult");
}

#[test]
fn parallel_guide_is_locally_linked_and_covers_the_author_contract() {
    let root = workspace_root();
    let guide = read(&root.join("docs/parallel-execution.md"));
    for term in [
        "`spawn`",
        "named join",
        "`joinall()`",
        "`detach(task);`",
        "deep copy",
        "forked child",
        "foreground outcome",
        "terminal outcome",
        "manually drive",
        "bounded",
        "`--workers`",
        "canonical IR identity",
        "physically resubmitted",
    ] {
        assert!(guide.contains(term), "guide omitted {term}");
    }
    for (index, target) in [
        ("README.md", "docs/parallel-execution.md"),
        ("README.md", "examples/parallel-execution/main.gnt"),
        ("docs/README.md", "parallel-execution.md"),
        ("docs/README.md", "../examples/parallel-execution/main.gnt"),
    ] {
        assert!(
            read(&root.join(index)).contains(target),
            "{index}: {target}"
        );
        assert!(root.join(target.trim_start_matches("../")).exists() || index == "docs/README.md");
    }

    let contract: Contract = serde_json::from_slice(
        &fs::read(root.join("protocol/conformance/async-execution-contract-v1.json"))
            .unwrap_or_else(|error| panic!("could not read async contract: {error}")),
    )
    .unwrap_or_else(|error| panic!("could not decode async contract: {error}"));
    let mut owned = contract
        .requirement_assignments
        .into_iter()
        .filter(|row| row.evidence_owners.iter().any(|owner| owner == ISSUE))
        .map(|row| (row.requirement, row.clause, row.profiles))
        .collect::<Vec<_>>();
    owned.sort();
    assert_eq!(
        owned,
        [
            (
                "GNT-1.0".to_owned(),
                "clause-001".to_owned(),
                profiles(&[
                    "analyzer",
                    "concurrent-evaluator",
                    "durable-runtime",
                    "embedding",
                    "evaluator",
                    "frontend"
                ])
            ),
            (
                "GNT-10.13".to_owned(),
                "clause-001".to_owned(),
                profiles(&[
                    "concurrent-evaluator",
                    "durable-runtime",
                    "embedding",
                    "evaluator"
                ])
            ),
            (
                "GNT-15.0".to_owned(),
                "clause-005".to_owned(),
                profiles(&["embedding"])
            ),
            (
                "GNT-15.1".to_owned(),
                "clause-001".to_owned(),
                profiles(&["embedding"])
            ),
            (
                "GNT-15.7".to_owned(),
                "clause-001".to_owned(),
                profiles(&["embedding"])
            ),
            (
                "GNT-15.8".to_owned(),
                "clause-001".to_owned(),
                profiles(&["embedding"])
            ),
            (
                "GNT-2.1".to_owned(),
                "clause-001".to_owned(),
                profiles(&[
                    "analyzer",
                    "concurrent-evaluator",
                    "durable-runtime",
                    "embedding",
                    "evaluator",
                    "frontend"
                ])
            ),
        ]
    );
}

fn profiles(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}
