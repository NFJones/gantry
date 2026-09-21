//! Public conformance for the value-storage contract of `GNT-GP-VALUE-PERF-001`, pinned to the
//! storage vocabulary of `crates/gantry-ir/src/scalar.rs` and the specification anchors it cites.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{ByteBufferValue, RESOURCE_CLAUSES, ScalarQuota, StorageStrategy};

/// The workspace root of this checkout.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("the conformance crate lives under the workspace root"))
}

/// The published storage note.
fn read_note() -> String {
    fs::read_to_string(workspace_root().join("docs/value-storage-model.md"))
        .unwrap_or_else(|error| panic!("the value-storage note is readable: {error}"))
}

#[test]
fn value_storage_note_names_the_declared_strategies_and_contracts() {
    let note = read_note();
    for strategy in StorageStrategy::ALL {
        assert!(
            note.contains(strategy.as_str()),
            "the note names the declared strategy `{}`",
            strategy.as_str()
        );
    }
    for required in [
        "StorageStrategy::EagerCopy",
        "StorageStrategy::CopyOnWrite",
        "StorageStrategy::Reuse",
        "ByteBufferValue",
        "ScalarQuota",
        "duplication_work",
        "write_work",
        "alias",
        "scalar-storage-strategy-divergence",
        "GNT-35.11",
        "live-value budget",
        "no allocation identity",
        "no reference count",
        "no collector phase or timing",
        "no sharing layout",
        "no cache state",
    ] {
        assert!(note.contains(required), "the note names `{required}`");
    }
    for clause in [
        "GNT-28.2-logical-measures-and-representation-equivalence",
        "GNT-28.5-closed-quota-families-and-owners",
    ] {
        assert!(
            RESOURCE_CLAUSES.contains(&clause),
            "the specification declares `{clause}`"
        );
        assert!(note.contains(clause), "the note names `{clause}`");
    }
}

#[test]
fn storage_strategies_agree_on_semantic_state_and_differ_only_in_physical_work() {
    let octets = b"gantry-value-storage".to_vec();
    let mut values = Vec::new();
    for strategy in StorageStrategy::ALL {
        let value = ByteBufferValue::with_octets(
            strategy,
            ScalarQuota::charged(64, 0)
                .unwrap_or_else(|error| panic!("the quota is admitted: {error}")),
            octets.clone(),
        )
        .unwrap_or_else(|error| panic!("the octets fit the quota: {error}"));
        assert_eq!(value.octets(), octets.as_slice());
        assert_eq!(value.strategy().as_str(), strategy.as_str());
        values.push(value);
    }
    for pair in values.windows(2) {
        assert_eq!(pair[0].octets(), pair[1].octets());
        assert_eq!(
            pair[0].quota(),
            pair[1].quota(),
            "the semantic charge is identical across strategies"
        );
    }
    let mut aliased = values
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("a value exists"));
    let second = aliased.alias();
    assert_eq!(aliased.octets(), second.octets());
    assert_eq!(
        StorageStrategy::EagerCopy.duplication_work(octets.len()),
        octets.len()
    );
    assert_eq!(
        StorageStrategy::CopyOnWrite.duplication_work(octets.len()),
        0
    );
    assert_eq!(StorageStrategy::Reuse.duplication_work(octets.len()), 0);
    assert_eq!(
        StorageStrategy::CopyOnWrite.write_work(octets.len()),
        octets.len()
    );
    assert_eq!(StorageStrategy::EagerCopy.write_work(octets.len()), 0);
    assert_eq!(StorageStrategy::Reuse.write_work(octets.len()), 0);
}
