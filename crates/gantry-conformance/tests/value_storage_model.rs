//! Public conformance for the value-storage contract of `GNT-GP-VALUE-PERF-001`, pinned to the
//! storage vocabulary of `crates/gantry-ir/src/scalar.rs` and the specification clauses it cites.

use std::collections::BTreeSet;
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

/// A buffer holding `octets` under `strategy`, charged against a 256-octet quota.
fn buffer(strategy: StorageStrategy, octets: &[u8]) -> ByteBufferValue {
    ByteBufferValue::with_octets(
        strategy,
        ScalarQuota::charged(256, 0)
            .unwrap_or_else(|error| panic!("the quota is admitted: {error}")),
        octets.to_vec(),
    )
    .unwrap_or_else(|error| panic!("the octets fit the quota: {error}"))
}

/// A refusal fingerprint: the diagnostic code's identity and the refusal's detail text.
fn refusal(error: gantry::ir::ScalarError) -> String {
    format!("{:?}: {}", error.code(), error)
}

#[test]
fn value_storage_note_states_the_declared_equivalence_contract() {
    let note = read_note();
    for strategy in StorageStrategy::ALL {
        let quoted = format!("`{}`", strategy.as_str());
        assert!(
            note.contains(&quoted),
            "the note names the declared strategy as `{}`",
            strategy.as_str()
        );
    }
    for required in [
        "StorageStrategy::EagerCopy",
        "StorageStrategy::CopyOnWrite",
        "StorageStrategy::Reuse",
        "storage-reuse",
        "ByteBufferValue",
        "ScalarQuota",
        "physical_work",
        "duplication_work",
        "write_work",
        "identical octets",
        "identical quota charges",
        "identical refusals",
        "identical canonical text",
        "round-trip exactly",
        "refused rather than repaired",
        "scalar-storage-strategy-divergence",
        "GNT-35.11",
        "bytes, handles, and operations",
        "resource, owner, and durable-record",
        "logical charge vector",
        "not clause text",
        "no allocation identity",
        "no reference count",
        "no collector phase or timing",
        "no sharing layout",
        "no cache state",
    ] {
        assert!(note.contains(required), "the note states `{required}`");
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
fn storage_strategies_agree_on_octets_charges_and_refusals_for_one_operation_sequence() {
    let mut semantic = Vec::new();
    let mut work = Vec::new();
    for strategy in StorageStrategy::ALL {
        let mut value = buffer(strategy, b"gantry");
        for (octet, released) in [(b'a', 1_usize), (b'b', 2), (b'c', 3)] {
            value
                .append(octet)
                .unwrap_or_else(|error| panic!("appending is admitted: {error}"));
            value
                .extend(&[octet, octet])
                .unwrap_or_else(|error| panic!("extending is admitted: {error}"));
            let length = value.len().saturating_sub(released);
            value
                .truncate(length)
                .unwrap_or_else(|error| panic!("truncation is admitted: {error}"));
        }
        let mut alias = value.alias();
        let refusals = vec![
            refusal(
                value
                    .append(b'z')
                    .err()
                    .unwrap_or_else(|| panic!("an aliased buffer refuses mutation")),
            ),
            refusal(
                alias
                    .append(b'z')
                    .err()
                    .unwrap_or_else(|| panic!("the aliasing buffer refuses mutation")),
            ),
        ];
        let copy = value.independent_copy();
        semantic.push((value.octets().to_vec(), value.quota(), refusals));
        work.push((copy.octets().to_vec(), copy.physical_work()));
    }
    for pair in semantic.windows(2) {
        assert_eq!(pair[0].0, pair[1].0, "identical octets");
        assert_eq!(pair[0].1, pair[1].1, "identical quota charges");
        assert_eq!(pair[0].2, pair[1].2, "identical refusals");
        assert_eq!(
            pair[0].2[0], pair[0].2[1],
            "both handles refuse identically"
        );
        assert!(
            pair[0].2[0].contains("BufferSharedMutation"),
            "the refusal is the shared-buffer refusal: {}",
            pair[0].2[0]
        );
    }
    let copies = work
        .iter()
        .map(|(octets, _)| octets.clone())
        .collect::<Vec<_>>();
    for copy in &copies {
        assert_eq!(
            *copy, copies[0],
            "the independent copy holds the same octets"
        );
    }
    let distinct: BTreeSet<usize> = work.iter().map(|(_, physical)| *physical).collect();
    assert!(
        distinct.len() > 1,
        "physical work differs across strategies: {work:?}"
    );
    assert_eq!(StorageStrategy::EagerCopy.duplication_work(6), 6);
    assert_eq!(StorageStrategy::CopyOnWrite.duplication_work(6), 0);
    assert_eq!(StorageStrategy::Reuse.duplication_work(6), 0);
    assert_eq!(StorageStrategy::CopyOnWrite.write_work(6), 6);
    assert_eq!(StorageStrategy::EagerCopy.write_work(6), 0);
    assert_eq!(StorageStrategy::Reuse.write_work(6), 0);
}
