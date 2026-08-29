//! Repository development commands for Gantry.

mod governance;
mod protocol;
mod requirements;
mod unicode;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use cargo_metadata::MetadataCommand;

const EXPECTED_PACKAGES: &[&str] = &[
    "gantry",
    "gantry-cli",
    "gantry-conformance",
    "gantry-core",
    "gantry-host",
    "xtask",
];

const ALLOWED_EDGES: &[(&str, &str)] = &[
    ("gantry", "gantry-core"),
    ("gantry", "gantry-host"),
    ("gantry-cli", "gantry"),
    ("gantry-conformance", "gantry"),
    ("gantry-host", "gantry-core"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkspacePackage {
    name: String,
    publish_disabled: bool,
    dependencies: BTreeSet<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, subject] if command == "generate" && subject == "protocol" => {
            protocol::generate(&workspace_root()?)
        }
        [command, subject] if command == "generate" && subject == "requirements" => {
            requirements::generate(&workspace_root()?)
        }
        [command, subject] if command == "generate" && subject == "unicode" => {
            unicode::generate(&workspace_root()?)
        }
        [command, subject] if command == "check" && subject == "generated" => {
            let root = workspace_root()?;
            protocol::check_generated(&root)?;
            requirements::check_generated(&root)?;
            unicode::check_generated(&root)
        }
        [command, subject] if command == "check" && subject == "workspace" => check_workspace(),
        [command, subject] if command == "check" && subject == "governance" => {
            governance::check(&workspace_root()?)
        }
        _ => Err(
            "usage: cargo run --locked -p xtask -- generate {protocol|requirements|unicode} | check {generated|governance|workspace}"
                .to_owned(),
        ),
    }
}

fn check_workspace() -> Result<(), String> {
    let root = workspace_root()?;
    let metadata = MetadataCommand::new()
        .current_dir(&root)
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()
        .map_err(|error| format!("cargo metadata failed: {error}"))?;
    let workspace_ids = metadata.workspace_members.iter().collect::<BTreeSet<_>>();
    let workspace_names = metadata
        .packages
        .iter()
        .filter(|package| workspace_ids.contains(&package.id))
        .map(|package| package.name.to_string())
        .collect::<BTreeSet<_>>();
    let packages = metadata
        .packages
        .iter()
        .filter(|package| workspace_ids.contains(&package.id))
        .map(|package| WorkspacePackage {
            name: package.name.to_string(),
            publish_disabled: package.publish.as_ref().is_some_and(Vec::is_empty),
            dependencies: package
                .dependencies
                .iter()
                .map(|dependency| dependency.name.to_string())
                .filter(|dependency| workspace_names.contains(dependency))
                .collect(),
        })
        .collect::<Vec<_>>();

    validate_graph(&packages)?;
    validate_facade_features(&metadata)?;
    check_feature_matrix(&root)?;
    println!("workspace graph and facade feature matrix are valid");
    Ok(())
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask manifest has no workspace parent".to_owned())
}

fn validate_graph(packages: &[WorkspacePackage]) -> Result<(), String> {
    let actual_names = packages
        .iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected_names = EXPECTED_PACKAGES.iter().copied().collect::<BTreeSet<_>>();
    if actual_names != expected_names {
        return Err(format!(
            "workspace packages differ: expected {expected_names:?}, found {actual_names:?}"
        ));
    }

    let allowed = ALLOWED_EDGES.iter().copied().collect::<BTreeSet<_>>();
    for package in packages {
        if package.name != "gantry" && !package.publish_disabled {
            return Err(format!(
                "workspace package {} must set publish = false",
                package.name
            ));
        }
        for dependency in &package.dependencies {
            if !allowed.contains(&(package.name.as_str(), dependency.as_str())) {
                return Err(format!(
                    "forbidden workspace edge: {} -> {dependency}",
                    package.name
                ));
            }
        }
    }
    Ok(())
}

fn validate_facade_features(metadata: &cargo_metadata::Metadata) -> Result<(), String> {
    let package = metadata
        .packages
        .iter()
        .find(|package| package.name == "gantry")
        .ok_or_else(|| "gantry facade package is absent".to_owned())?;
    let required = BTreeMap::from([
        ("default", BTreeSet::from(["evaluator"])),
        ("frontend", BTreeSet::new()),
        ("analyzer", BTreeSet::from(["frontend"])),
        ("evaluator", BTreeSet::from(["analyzer"])),
        ("concurrent", BTreeSet::from(["evaluator"])),
        ("durable", BTreeSet::from(["evaluator"])),
    ]);

    for (feature, expected_members) in required {
        let actual_members = package
            .features
            .get(feature)
            .ok_or_else(|| format!("gantry feature {feature} is absent"))?
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if actual_members != expected_members {
            return Err(format!(
                "gantry feature {feature} must contain exactly {expected_members:?}, found {actual_members:?}"
            ));
        }
    }
    Ok(())
}

fn check_feature_matrix(root: &Path) -> Result<(), String> {
    let combinations: &[&[&str]] = &[
        &[],
        &["frontend"],
        &["analyzer"],
        &["evaluator"],
        &["concurrent"],
        &["durable"],
        &["concurrent", "durable"],
    ];

    for features in combinations {
        let mut command = Command::new("cargo");
        command.current_dir(root).args([
            "test",
            "--locked",
            "-p",
            "gantry",
            "--lib",
            "--no-default-features",
        ]);
        if !features.is_empty() {
            command.args(["--features", &features.join(",")]);
        }
        let status = command
            .status()
            .map_err(|error| format!("could not run facade feature test: {error}"))?;
        if !status.success() {
            return Err(format!("facade feature test failed for {features:?}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{WorkspacePackage, validate_graph};
    use std::collections::BTreeSet;

    fn package(name: &str, publish_disabled: bool, dependencies: &[&str]) -> WorkspacePackage {
        WorkspacePackage {
            name: name.to_owned(),
            publish_disabled,
            dependencies: dependencies
                .iter()
                .map(|dependency| (*dependency).to_owned())
                .collect::<BTreeSet<_>>(),
        }
    }

    fn valid_graph() -> Vec<WorkspacePackage> {
        vec![
            package("gantry", false, &["gantry-core", "gantry-host"]),
            package("gantry-cli", true, &["gantry"]),
            package("gantry-conformance", true, &["gantry"]),
            package("gantry-core", true, &[]),
            package("gantry-host", true, &["gantry-core"]),
            package("xtask", true, &[]),
        ]
    }

    #[test]
    fn accepts_the_bootstrap_dependency_graph() {
        assert_eq!(validate_graph(&valid_graph()), Ok(()));
    }

    #[test]
    fn rejects_a_generator_dependency_on_production() {
        let mut packages = valid_graph();
        let xtask = packages.iter_mut().find(|package| package.name == "xtask");
        assert!(xtask.is_some());
        if let Some(xtask) = xtask {
            xtask.dependencies.insert("gantry-core".to_owned());
        }

        let error = validate_graph(&packages);
        assert!(matches!(error, Err(message) if message.contains("xtask -> gantry-core")));
    }
}
