//! Deterministic one-way generation from canonical protocol inputs.

mod embedding;
mod ir;
mod portable;
mod publication;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const CATALOG_PATH: &str = "protocol/catalogs/profiles-v1.json";
const GOLDEN_PATH: &str = "protocol/goldens/profiles-v1.canonical.json";
const OUTPUT_PATH: &str = "crates/gantry-core/src/generated/profiles.rs";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProfileCatalog {
    catalog: String,
    major: u64,
    minor: u64,
    profiles: Vec<ProfileInput>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProfileInput {
    name: String,
    rust_name: String,
    requires: Vec<String>,
}

/// Generates all currently materialized protocol bindings.
pub(crate) fn generate(root: &Path) -> Result<(), String> {
    let profiles_changed = generate_protocol(root)?;
    let embedding_changed = embedding::generate(root)?;
    let ir_changed = ir::generate(root)?;
    let portable_changed = portable::generate(root)?;
    publication::check_generated(root)?;
    if profiles_changed {
        println!("generated {OUTPUT_PATH}");
    }
    if !profiles_changed && !embedding_changed && !ir_changed && !portable_changed {
        println!("protocol bindings are already current");
    }
    Ok(())
}

/// Checks all currently materialized generated protocol bindings without writing.
pub(crate) fn check_generated(root: &Path) -> Result<(), String> {
    let catalog = load_catalog(root)?;
    let expected = render_rust(&catalog);
    let path = root.join(OUTPUT_PATH);
    let actual =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if actual != expected.as_bytes() {
        return Err(format!(
            "{OUTPUT_PATH} is stale; run `cargo run --locked -p xtask -- generate protocol`"
        ));
    }
    embedding::check_generated(root)?;
    ir::check_generated(root)?;
    portable::check_generated(root)?;
    publication::check_generated(root)?;
    println!("generated protocol bindings are current");
    Ok(())
}

fn generate_protocol(root: &Path) -> Result<bool, String> {
    let catalog = load_catalog(root)?;
    let output = render_rust(&catalog);
    write_atomic_if_changed(&root.join(OUTPUT_PATH), output.as_bytes())
}

fn load_catalog(root: &Path) -> Result<ProfileCatalog, String> {
    let catalog = parse_catalog(&root.join(CATALOG_PATH))?;
    validate_catalog(&catalog)?;

    let golden_path = root.join(GOLDEN_PATH);
    let golden_bytes = fs::read(&golden_path)
        .map_err(|error| format!("could not read {}: {error}", golden_path.display()))?;
    let expected_golden = render_canonical_json(&catalog);
    if golden_bytes != expected_golden.as_bytes() {
        return Err(format!(
            "{} does not contain the canonical catalog encoding",
            golden_path.display()
        ));
    }
    Ok(catalog)
}

fn parse_catalog(path: &Path) -> Result<ProfileCatalog, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid profile catalog {}: {error}", path.display()))
}

fn validate_catalog(catalog: &ProfileCatalog) -> Result<(), String> {
    if catalog.catalog != "gantry.profiles" || (catalog.major, catalog.minor) != (1, 0) {
        return Err("profile catalog must identify gantry.profiles version 1.0".to_owned());
    }
    if catalog.profiles.is_empty() {
        return Err("profile catalog must not be empty".to_owned());
    }

    let mut names = BTreeSet::new();
    let mut rust_names = BTreeSet::new();
    let mut prior_name: Option<&str> = None;
    for profile in &catalog.profiles {
        validate_wire_name(&profile.name)?;
        validate_rust_name(&profile.rust_name)?;
        if prior_name.is_some_and(|prior| prior >= profile.name.as_str()) {
            return Err("profiles must be strictly ordered by wire name".to_owned());
        }
        prior_name = Some(&profile.name);
        if !names.insert(profile.name.as_str()) {
            return Err(format!("duplicate profile name {}", profile.name));
        }
        if !rust_names.insert(profile.rust_name.as_str()) {
            return Err(format!("duplicate profile Rust name {}", profile.rust_name));
        }

        let mut prior_requirement: Option<&str> = None;
        for requirement in &profile.requires {
            validate_wire_name(requirement)?;
            if prior_requirement.is_some_and(|prior| prior >= requirement.as_str()) {
                return Err(format!(
                    "requirements for {} must be unique and strictly ordered",
                    profile.name
                ));
            }
            prior_requirement = Some(requirement);
        }
    }

    let profiles = catalog
        .profiles
        .iter()
        .map(|profile| (profile.name.as_str(), profile))
        .collect::<BTreeMap<_, _>>();
    for profile in &catalog.profiles {
        for requirement in &profile.requires {
            if requirement == &profile.name {
                return Err(format!("profile {} cannot require itself", profile.name));
            }
            if !profiles.contains_key(requirement.as_str()) {
                return Err(format!(
                    "profile {} requires unknown profile {requirement}",
                    profile.name
                ));
            }
        }
    }
    reject_dependency_cycles(&profiles)
}

fn validate_wire_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.starts_with('-')
        || name.ends_with('-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    {
        return Err(format!("invalid profile wire name {name:?}"));
    }
    Ok(())
}

fn validate_rust_name(name: &str) -> Result<(), String> {
    let mut bytes = name.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_uppercase())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(format!("invalid profile Rust name {name:?}"));
    }
    Ok(())
}

fn reject_dependency_cycles(profiles: &BTreeMap<&str, &ProfileInput>) -> Result<(), String> {
    fn visit<'a>(
        name: &'a str,
        profiles: &BTreeMap<&'a str, &'a ProfileInput>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> Result<(), String> {
        if visited.contains(name) {
            return Ok(());
        }
        if !visiting.insert(name) {
            return Err(format!("profile dependency cycle includes {name}"));
        }
        for requirement in &profiles[name].requires {
            visit(requirement, profiles, visiting, visited)?;
        }
        visiting.remove(name);
        visited.insert(name);
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for name in profiles.keys().copied() {
        visit(name, profiles, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn render_canonical_json(catalog: &ProfileCatalog) -> String {
    let mut output = format!(
        "{{\"catalog\":\"{}\",\"major\":{},\"minor\":{},\"profiles\":[",
        catalog.catalog, catalog.major, catalog.minor
    );
    for (index, profile) in catalog.profiles.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&format!("{{\"name\":\"{}\",\"requires\":[", profile.name));
        for (requirement_index, requirement) in profile.requires.iter().enumerate() {
            if requirement_index > 0 {
                output.push(',');
            }
            output.push_str(&format!("\"{requirement}\""));
        }
        output.push_str(&format!("],\"rust_name\":\"{}\"}}", profile.rust_name));
    }
    output.push_str("]}\n");
    output
}

fn render_rust(catalog: &ProfileCatalog) -> String {
    let mut output = String::from(
        "// @generated by `cargo run --locked -p xtask -- generate protocol`.\n\
// Source: protocol/catalogs/profiles-v1.json. Do not edit manually.\n\n\
/// One named Gantry conformance profile.\n\
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]\n\
pub enum ConformanceProfile {\n",
    );
    for profile in &catalog.profiles {
        output.push_str(&format!(
            "    /// The `{}` profile.\n    {},\n",
            profile.name, profile.rust_name
        ));
    }
    output.push_str("}\n\nimpl ConformanceProfile {\n    /// Returns the exact portable profile name.\n    #[must_use]\n    pub const fn wire_name(self) -> &'static str {\n        match self {\n");
    for profile in &catalog.profiles {
        output.push_str(&format!(
            "            Self::{} => \"{}\",\n",
            profile.rust_name, profile.name
        ));
    }
    output.push_str(
        "        }\n    }\n}\n\n\
/// One profile and its direct prerequisite profiles.\n\
#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
pub struct ProfileDefinition {\n\
    /// The profile being defined.\n\
    pub profile: ConformanceProfile,\n\
    /// Direct prerequisite profiles in canonical order.\n\
    pub requires: &'static [ConformanceProfile],\n\
}\n\n\
/// All Gantry v1 profiles in canonical wire-name order.\n\
pub const PROFILE_DEFINITIONS: &[ProfileDefinition] = &[\n",
    );
    for profile in &catalog.profiles {
        output.push_str(&format!(
            "    ProfileDefinition {{\n        profile: ConformanceProfile::{},\n        requires: &[",
            profile.rust_name
        ));
        for (index, requirement) in profile.requires.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            output.push_str(&format!(
                "ConformanceProfile::{}",
                catalog
                    .profiles
                    .iter()
                    .find(|candidate| &candidate.name == requirement)
                    .map(|candidate| candidate.rust_name.as_str())
                    .unwrap_or_default()
            ));
        }
        output.push_str("],\n    },\n");
    }
    output.push_str("];\n");
    output
}

pub(super) fn write_atomic_if_changed(path: &Path, contents: &[u8]) -> Result<bool, String> {
    if fs::read(path).is_ok_and(|existing| existing == contents) {
        return Ok(false);
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
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
    use super::{ProfileCatalog, ProfileInput, generate_protocol, render_rust, validate_catalog};
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    fn catalog() -> ProfileCatalog {
        ProfileCatalog {
            catalog: "gantry.profiles".to_owned(),
            major: 1,
            minor: 0,
            profiles: vec![
                ProfileInput {
                    name: "analyzer".to_owned(),
                    rust_name: "Analyzer".to_owned(),
                    requires: vec!["frontend".to_owned()],
                },
                ProfileInput {
                    name: "frontend".to_owned(),
                    rust_name: "Frontend".to_owned(),
                    requires: vec![],
                },
            ],
        }
    }

    #[test]
    fn renders_the_same_binding_for_the_same_catalog() {
        let catalog = catalog();
        assert_eq!(validate_catalog(&catalog), Ok(()));
        assert_eq!(render_rust(&catalog), render_rust(&catalog));
    }

    #[test]
    fn rejects_duplicate_rust_names() {
        let mut catalog = catalog();
        catalog.profiles[1].rust_name = "Analyzer".to_owned();
        let error = validate_catalog(&catalog);
        assert!(matches!(error, Err(message) if message.contains("duplicate profile Rust name")));
    }

    #[test]
    fn rejects_unknown_dependencies() {
        let mut catalog = catalog();
        catalog.profiles[0].requires = vec!["missing".to_owned()];
        let error = validate_catalog(&catalog);
        assert!(matches!(error, Err(message) if message.contains("unknown profile missing")));
    }

    #[test]
    fn rejects_noncanonical_profile_order() {
        let mut catalog = catalog();
        catalog.profiles.reverse();
        let error = validate_catalog(&catalog);
        assert!(matches!(error, Err(message) if message.contains("strictly ordered")));
    }

    #[test]
    fn generation_is_an_idempotent_no_op() {
        let root = temporary_root();
        let catalog = catalog();
        let pretty = serde_json::to_vec_pretty(&catalog_for_json(&catalog));
        assert!(pretty.is_ok());
        let pretty = pretty.unwrap_or_default();
        write_fixture(&root, super::CATALOG_PATH, &pretty);
        write_fixture(
            &root,
            super::GOLDEN_PATH,
            super::render_canonical_json(&catalog).as_bytes(),
        );

        assert_eq!(generate_protocol(&root), Ok(true));
        assert_eq!(generate_protocol(&root), Ok(false));
        assert!(root.join(super::OUTPUT_PATH).is_file());
        assert!(fs::remove_dir_all(root).is_ok());
    }

    fn catalog_for_json(catalog: &ProfileCatalog) -> serde_json::Value {
        serde_json::json!({
            "catalog": catalog.catalog,
            "major": catalog.major,
            "minor": catalog.minor,
            "profiles": catalog.profiles.iter().map(|profile| serde_json::json!({
                "name": profile.name,
                "rust_name": profile.rust_name,
                "requires": profile.requires,
            })).collect::<Vec<_>>(),
        })
    }

    fn temporary_root() -> std::path::PathBuf {
        let suffix = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "gantry-xtask-protocol-{}-{suffix}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        assert!(fs::create_dir_all(&root).is_ok());
        root
    }

    fn write_fixture(root: &std::path::Path, relative: &str, contents: &[u8]) {
        let path = root.join(relative);
        let parent = path.parent();
        assert!(parent.is_some());
        if let Some(parent) = parent {
            assert!(fs::create_dir_all(parent).is_ok());
        }
        assert!(fs::write(path, contents).is_ok());
    }
}
