//! Fresh identity and UTC package-service contract coverage.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::Command;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{
    FreshIdentityAllocator, HostError, IdentityAllocationError, UtcClock,
};
use gantry::portable::IdentityKind;
use gantry::timestamp::UtcTimestamp;
use gantry_conformance::services::{DeterministicIdentitySource, DeterministicUtcClock};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ServiceVectors {
    format: String,
    timestamps: Vec<TimestampVector>,
    identity_allocations: Vec<IdentityVector>,
}

#[derive(Debug, Deserialize)]
struct TimestampVector {
    seconds: i64,
    microseconds: u32,
    expected: Option<String>,
    expected_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdentityVector {
    kind: String,
    scripted_material: Vec<String>,
    expected: Option<String>,
    expected_error: Option<String>,
    expected_calls: usize,
}

#[test]
fn fresh_allocator_retries_same_kind_collisions_at_most_three_times() {
    let allocator = FreshIdentityAllocator::default();
    let source = DeterministicIdentitySource::new([Ok([1; 32]), Ok([1; 32]), Ok([2; 32])]);
    let first = allocator.allocate(&source, IdentityKind::Activity);
    let second = allocator.allocate(&source, IdentityKind::Activity);
    assert!(first.is_ok() && second.is_ok());
    assert_ne!(first, second);
    assert_eq!(source.calls(), vec![IdentityKind::Activity; 3]);

    let exhausted = DeterministicIdentitySource::new([Ok([2; 32]), Ok([2; 32]), Ok([2; 32])]);
    assert_eq!(
        allocator.allocate(&exhausted, IdentityKind::Activity),
        Err(IdentityAllocationError::CollisionLimit)
    );
    assert_eq!(
        IdentityAllocationError::CollisionLimit.portable_code(),
        "identity-generation-failure"
    );
    assert_eq!(exhausted.calls().len(), 3);
}

#[test]
fn fresh_allocator_is_kind_scoped_and_propagates_source_failure() {
    let allocator = FreshIdentityAllocator::default();
    let activity = DeterministicIdentitySource::new([Ok([7; 32])]);
    let event = DeterministicIdentitySource::new([Ok([7; 32])]);
    assert!(
        allocator
            .allocate(&activity, IdentityKind::Activity)
            .is_ok()
    );
    assert!(allocator.allocate(&event, IdentityKind::Event).is_ok());
    assert_eq!(
        allocator.allocate(&activity, IdentityKind::Task),
        Err(IdentityAllocationError::WrongOrigin)
    );

    let failure = HostError {
        code: Arc::from("randomness-failure"),
        protected_diagnostic: None,
    };
    let source = DeterministicIdentitySource::new([Err(failure.clone())]);
    assert_eq!(
        allocator.allocate(&source, IdentityKind::DeliveryAttempt),
        Err(IdentityAllocationError::Source(failure))
    );
}

#[test]
fn deterministic_clock_preserves_exact_timestamp_and_failure() {
    let timestamp = UtcTimestamp::from_unix_seconds(0, 42);
    assert!(timestamp.is_ok());
    let timestamp = timestamp.unwrap_or_else(|_| unreachable!("checked above"));
    let failure = HostError {
        code: Arc::from("clock-failure"),
        protected_diagnostic: None,
    };
    let clock = DeterministicUtcClock::new([Ok(timestamp.clone()), Err(failure.clone())]);
    assert_eq!(block_on(clock.utc_now()), Ok(timestamp));
    assert_eq!(block_on(clock.utc_now()), Err(failure));
}

#[test]
fn canonical_package_service_vectors_pass_through_public_contracts() {
    let schema: serde_json::Value =
        read_json(&workspace_root().join("protocol/schemas/package-services-v1.schema.json"));
    assert_eq!(
        schema["$id"],
        "https://gantry.invalid/protocol/package-services/v1/schema.json"
    );
    assert_eq!(
        schema["$defs"]["fresh_identity_material"]["pattern"],
        "^[0-9a-f]{64}$"
    );
    assert_eq!(
        schema["$defs"]["utc_timestamp"]["pattern"],
        "^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\\.[0-9]{6}Z$"
    );
    let vectors: ServiceVectors =
        read_json(&workspace_root().join("protocol/goldens/package-service-vectors-v1.json"));
    assert_eq!(vectors.format, "gantry.package-service-vectors/v1");

    for vector in vectors.timestamps {
        let result = UtcTimestamp::from_unix_seconds(vector.seconds, vector.microseconds);
        assert_eq!(
            result.as_ref().map(ToString::to_string).ok(),
            vector.expected
        );
        assert_eq!(
            result.err().map(|error| error.to_string()),
            vector.expected_error
        );
    }

    for vector in vectors.identity_allocations {
        let kind = IdentityKind::from_wire_name(&vector.kind);
        assert!(kind.is_some());
        let kind = kind.unwrap_or_else(|| unreachable!("checked above"));
        let responses = vector
            .scripted_material
            .iter()
            .map(|value| {
                decode_material(value).map_err(|code| HostError {
                    code: Arc::from(code),
                    protected_diagnostic: None,
                })
            })
            .collect::<Vec<_>>();
        let source = DeterministicIdentitySource::new(responses);
        let allocator = FreshIdentityAllocator::default();
        let result = allocator.allocate(&source, kind);
        assert_eq!(
            result.as_ref().map(ToString::to_string).ok(),
            vector.expected
        );
        assert_eq!(
            result.err().map(|error| error.portable_code().to_owned()),
            vector.expected_error
        );
        assert_eq!(source.calls().len(), vector.expected_calls);
    }
}

#[test]
fn frontend_and_analyzer_cli_compositions_run_service_contract_tests() {
    for feature in ["frontend", "analyzer"] {
        let status = Command::new("cargo")
            .current_dir(workspace_root())
            .env(
                "CARGO_TARGET_DIR",
                workspace_root().join("target/conformance-cli-services"),
            )
            .args([
                "test",
                "--locked",
                "-p",
                "gantry-cli",
                "--bin",
                "gantry",
                "--no-default-features",
                "--features",
                feature,
                "services::tests",
            ])
            .status();
        assert!(status.is_ok(), "could not run {feature} CLI service tests");
        assert!(
            status
                .unwrap_or_else(|_| unreachable!("checked above"))
                .success(),
            "{feature} CLI service tests failed"
        );
    }
}

fn decode_material(value: &str) -> Result<[u8; 32], &'static str> {
    if value == "failure" {
        return Err("identity-generation-failure");
    }
    if value.len() != 64 {
        return Err("identity-generation-failure");
    }
    let mut material = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| "identity-generation-failure")?;
        material[index] =
            u8::from_str_radix(text, 16).map_err(|_| "identity-generation-failure")?;
    }
    Ok(material)
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("deterministic clock unexpectedly remained pending"),
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path);
    assert!(bytes.is_ok(), "could not read {}", path.display());
    let value =
        bytes.and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other));
    assert!(value.is_ok(), "could not decode {}", path.display());
    value.unwrap_or_else(|_| unreachable!("checked above"))
}
