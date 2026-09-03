//! Independent checks of canonical protocol inputs and public generated bindings.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gantry::host::contracts::{EmbeddingVersion, EnvelopeError, HostRequest};
use gantry::host::embedding::{
    EMBEDDING_OPERATIONS, EMBEDDING_SPECIFICATION_REVISION, EmbeddingOperation, FAILURE_BOUNDARIES,
    TRAIT_BOUNDS,
};
use gantry::identity::ProtocolIdentity;
use gantry::portable::{
    CONFIGURATION_FIELDS, EVENT_KINDS, IDENTITY_KINDS, IdentityKind, MAXIMUM_DIRECTIVE_INTEGER,
    PORTABLE_SPECIFICATION_REVISION, PORTABLE_VOCABULARIES, PROTOCOL_FAMILY_DEFINITIONS,
};
use gantry::{PROFILE_DEFINITIONS, PROFILE_SUPERSEDED_SPECIFICATION_REVISION};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProfileCatalog {
    catalog: String,
    claims_enabled: bool,
    major: u64,
    minor: u64,
    specification_revision: String,
    superseded_specification_revision: String,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableVectors {
    format: String,
    identity_derivations: Vec<IdentityDerivationVector>,
    invalid_identities: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityDerivationVector {
    kind: String,
    canonical_key: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingNegativeVectors {
    format: String,
    cases: Vec<EmbeddingNegativeCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingNegativeCase {
    name: String,
    major: u64,
    minor: u64,
    operation: String,
}

#[test]
fn canonical_profile_catalog_matches_the_public_binding() {
    let catalog: ProfileCatalog = read_json(&protocol_root().join("catalogs/profiles-v1.json"));
    let golden: ProfileCatalog =
        read_json(&protocol_root().join("goldens/profiles-v1.canonical.json"));
    assert_eq!(catalog, golden);
    assert_eq!(catalog.catalog, "gantry.profiles");
    assert_eq!((catalog.major, catalog.minor), (1, 0));
    assert_eq!(catalog.claims_enabled, gantry::PROFILE_CLAIMS_ENABLED);
    assert_eq!(
        catalog.specification_revision,
        gantry::PROFILE_SPECIFICATION_REVISION
    );
    assert_eq!(
        catalog.superseded_specification_revision,
        PROFILE_SUPERSEDED_SPECIFICATION_REVISION
    );
    assert!(!catalog.claims_enabled);
    assert!(gantry::advertised_profiles().is_empty());

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

#[test]
fn portable_catalog_matches_its_golden_schema_and_public_binding() {
    let root = protocol_root();
    let catalog_path = root.join("catalogs/portable-contracts-v1.json");
    let golden_path = root.join("goldens/portable-contracts-v1.canonical.json");
    let schema: serde_json::Value =
        read_json(&root.join("schemas/portable-contracts-v1.schema.json"));
    let catalog: serde_json::Value = read_json(&catalog_path);
    let golden: serde_json::Value = read_json(&golden_path);

    assert_eq!(catalog, golden);
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(catalog["catalog"], "gantry.portable-contracts");
    assert_eq!(catalog["major"], 1);
    assert_eq!(catalog["minor"], 0);
    assert_eq!(
        catalog["specification_revision"],
        PORTABLE_SPECIFICATION_REVISION
    );
    assert_eq!(
        catalog["maximum_directive_integer"],
        MAXIMUM_DIRECTIVE_INTEGER.to_string()
    );

    let specification = fs::read(root.join("../SPEC.md"));
    assert!(specification.is_ok());
    let revision = specification
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .unwrap_or_else(|_| unreachable!("assertion above checks the specification read"));
    assert_eq!(revision, PORTABLE_SPECIFICATION_REVISION);

    let identities = catalog["identity_kinds"]
        .as_array()
        .unwrap_or_else(|| unreachable!("canonical catalog identities are an array"));
    let public_identities = IDENTITY_KINDS
        .iter()
        .map(|kind| (kind.wire_name(), kind.origin().wire_name()))
        .collect::<Vec<_>>();
    let canonical_identities = identities
        .iter()
        .map(|entry| {
            (
                entry["wire"]
                    .as_str()
                    .unwrap_or_else(|| unreachable!("identity wire name is a string")),
                entry["origin"]
                    .as_str()
                    .unwrap_or_else(|| unreachable!("identity origin is a string")),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(public_identities, canonical_identities);

    let families = catalog["protocol_families"]
        .as_array()
        .unwrap_or_else(|| unreachable!("canonical protocol families are an array"));
    let public_families = PROTOCOL_FAMILY_DEFINITIONS
        .iter()
        .map(|definition| {
            (
                definition.family.wire_name(),
                definition.major,
                definition.minor,
            )
        })
        .collect::<Vec<_>>();
    let canonical_families = families
        .iter()
        .map(|entry| {
            (
                entry["wire"]
                    .as_str()
                    .unwrap_or_else(|| unreachable!("protocol family name is a string")),
                entry["major"]
                    .as_u64()
                    .unwrap_or_else(|| unreachable!("protocol major is unsigned")),
                entry["minor"]
                    .as_u64()
                    .unwrap_or_else(|| unreachable!("protocol minor is unsigned")),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(public_families, canonical_families);

    let vocabularies = catalog["vocabularies"]
        .as_array()
        .unwrap_or_else(|| unreachable!("canonical vocabularies are an array"));
    let public_vocabularies = PORTABLE_VOCABULARIES
        .iter()
        .map(|definition| (definition.name, definition.values.to_vec()))
        .collect::<Vec<_>>();
    let canonical_vocabularies = vocabularies
        .iter()
        .map(|entry| {
            let values = entry["values"]
                .as_array()
                .unwrap_or_else(|| unreachable!("vocabulary values are an array"))
                .iter()
                .map(|value| {
                    value["wire"]
                        .as_str()
                        .unwrap_or_else(|| unreachable!("vocabulary wire name is a string"))
                })
                .collect::<Vec<_>>();
            (
                entry["name"]
                    .as_str()
                    .unwrap_or_else(|| unreachable!("vocabulary name is a string")),
                values,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(public_vocabularies, canonical_vocabularies);

    let events = catalog["events"]
        .as_array()
        .unwrap_or_else(|| unreachable!("canonical events are an array"));
    let public_events = EVENT_KINDS
        .iter()
        .map(|definition| (definition.kind.wire_name(), definition.layer.wire_name()))
        .collect::<Vec<_>>();
    let canonical_events = events
        .iter()
        .map(|entry| {
            (
                entry["wire"]
                    .as_str()
                    .unwrap_or_else(|| unreachable!("event wire name is a string")),
                entry["layer"]
                    .as_str()
                    .unwrap_or_else(|| unreachable!("event layer is a string")),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(public_events, canonical_events);

    let configuration = catalog["configuration_fields"]
        .as_array()
        .unwrap_or_else(|| unreachable!("configuration metadata is an array"));
    assert_eq!(CONFIGURATION_FIELDS.len(), configuration.len());
    for (public, canonical) in CONFIGURATION_FIELDS.iter().zip(configuration) {
        assert_eq!(
            public.field.wire_name(),
            canonical["wire"]
                .as_str()
                .unwrap_or_else(|| unreachable!("configuration wire name is a string"))
        );
        assert_eq!(
            public.class.wire_name(),
            canonical["class"]
                .as_str()
                .unwrap_or_else(|| unreachable!("configuration class is a string"))
        );
        assert_eq!(public.default, canonical["default"].as_str());
        assert_eq!(public.zero_allowed, canonical["zero_allowed"].as_bool());
        assert_eq!(public.maximum, canonical["maximum"].as_str());
    }
}

#[test]
fn portable_identity_vectors_cover_derivation_and_strict_rejection() {
    let vectors: PortableVectors =
        read_json(&protocol_root().join("goldens/portable-contract-vectors-v1.json"));
    assert_eq!(vectors.format, "gantry.portable-contract-vectors/v1");
    for vector in vectors.identity_derivations {
        let kind = IdentityKind::from_wire_name(&vector.kind);
        assert!(kind.is_some());
        let derived = kind
            .and_then(|kind| ProtocolIdentity::derive(kind, vector.canonical_key.as_bytes()).ok());
        assert_eq!(
            derived.map(|identity| identity.to_string()),
            Some(vector.expected)
        );
    }
    for invalid in vectors.invalid_identities {
        assert!(
            ProtocolIdentity::parse(&invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn embedding_catalog_matches_its_golden_schema_and_public_binding() {
    let root = protocol_root();
    let catalog: serde_json::Value = read_json(&root.join("catalogs/embedding-contracts-v1.json"));
    let golden: serde_json::Value =
        read_json(&root.join("goldens/embedding-contracts-v1.canonical.json"));
    let schema: serde_json::Value =
        read_json(&root.join("schemas/embedding-contracts-v1.schema.json"));

    assert_eq!(catalog, golden);
    assert_eq!(catalog["catalog"], "gantry.embedding-contracts");
    assert_eq!(catalog["major"], 1);
    assert_eq!(catalog["minor"], 0);
    assert_eq!(
        catalog["specification_revision"],
        EMBEDDING_SPECIFICATION_REVISION
    );
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["additionalProperties"], false);

    let operations = catalog["operations"]
        .as_array()
        .unwrap_or_else(|| unreachable!("embedding operations are an array"));
    assert_eq!(operations.len(), EMBEDDING_OPERATIONS.len());
    for (canonical, public) in operations.iter().zip(EMBEDDING_OPERATIONS) {
        assert_eq!(canonical["wire"], public.operation.wire_name());
        assert_eq!(canonical["service"], public.service.wire_name());
        assert_eq!(canonical["role"], public.role.wire_name());
        assert_eq!(canonical["acceptance"], public.acceptance);
        assert_eq!(canonical["idempotency"], public.idempotency);
        assert_eq!(canonical["cancellation"], public.cancellation);
        assert_eq!(canonical["async_kind"], public.async_kind.wire_name());
    }

    assert_eq!(
        catalog["failure_matrix"].as_array().map(Vec::len),
        Some(FAILURE_BOUNDARIES.len())
    );
    assert_eq!(
        catalog["trait_bounds"].as_array().map(Vec::len),
        Some(TRAIT_BOUNDS.len())
    );
}

#[test]
fn embedding_negative_vectors_reject_versions_and_unknown_operations() {
    let vectors: EmbeddingNegativeVectors =
        read_json(&protocol_root().join("goldens/embedding-envelope-negatives-v1.json"));
    assert_eq!(vectors.format, "gantry.embedding-envelope-negatives/v1");

    for case in vectors.cases {
        let version = EmbeddingVersion {
            major: case.major,
            minor: case.minor,
        };
        let operation = EmbeddingOperation::from_wire_name(&case.operation);
        match operation {
            Some(operation) => assert_eq!(
                HostRequest::new(version, operation, Arc::from(&b"{}"[..])),
                Err(EnvelopeError::UnsupportedVersion),
                "accepted {}",
                case.name
            ),
            None => assert!(
                matches!(
                    case.name.as_str(),
                    "unknown-operation" | "wrong-operation-case"
                ),
                "unexpected unknown operation fixture {}",
                case.name
            ),
        }
    }
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
