//! Independent checks of canonical protocol inputs and public generated bindings.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::PROFILE_DEFINITIONS;
use serde::Deserialize;

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProfileCatalog {
    catalog: String,
    major: u64,
    minor: u64,
    profiles: Vec<ProfileInput>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProfileInput {
    name: String,
    requires: Vec<String>,
    rust_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationInput {
    publication_index: Version,
    required_artifact_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Version {
    major: u64,
    minor: u64,
}

#[test]
fn canonical_profile_catalog_matches_the_public_binding() {
    let catalog: ProfileCatalog = read_json(&protocol_root().join("catalogs/profiles-v1.json"));
    let golden: ProfileCatalog =
        read_json(&protocol_root().join("goldens/profiles-v1.canonical.json"));
    assert_eq!(catalog, golden);
    assert_eq!(catalog.catalog, "gantry.profiles");
    assert_eq!((catalog.major, catalog.minor), (1, 0));

    let public = PROFILE_DEFINITIONS
        .iter()
        .map(|definition| {
            (
                definition.profile.wire_name(),
                definition
                    .requires
                    .iter()
                    .map(|profile| profile.wire_name())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let canonical = catalog
        .profiles
        .iter()
        .map(|profile| {
            (
                profile.name.as_str(),
                profile
                    .requires
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(public, canonical);
}

#[test]
fn canonical_schema_and_publication_skeleton_are_well_formed() {
    let schema: serde_json::Value =
        read_json(&protocol_root().join("schemas/profile-catalog-v1.schema.json"));
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );

    let publication: PublicationInput =
        read_json(&protocol_root().join("publication/artifacts-v1.json"));
    assert_eq!(
        publication.publication_index,
        Version { major: 1, minor: 0 }
    );
    let actual = publication
        .required_artifact_ids
        .into_iter()
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "gantry.authoring".to_owned(),
        "gantry.conformance".to_owned(),
        "gantry.embedding".to_owned(),
        "gantry.ir".to_owned(),
        "gantry.journal".to_owned(),
        "gantry.spec".to_owned(),
        "gantry.values".to_owned(),
    ]);
    assert_eq!(actual, expected);
}

fn protocol_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path);
    assert!(bytes.is_ok(), "could not read {}", path.display());
    let value =
        bytes.and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other));
    assert!(value.is_ok(), "could not decode {}", path.display());
    value.unwrap_or_else(|_| unreachable!("assertion above checks decoding"))
}
