//! Public conformance for the value-storage contract of `GNT-GP-VALUE-PERF-001`, pinned to the
//! storage vocabulary of `crates/gantry-ir/src/scalar.rs` and the specification clauses it cites.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{ByteBufferValue, RESOURCE_CLAUSES, ScalarQuota, StorageStrategy};
use gantry::ir::{BytesValue, IntegerValue, ScalarError, ScalarKind, ScalarWidth};

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

/// A refusal fingerprint from a fallible construction.
fn refusal_of(result: Result<IntegerValue, ScalarError>) -> String {
    match result {
        Ok(value) => panic!(
            "the construction is refused, not accepted as {}",
            value.value()
        ),
        Err(error) => refusal(error),
    }
}

/// The buffer's initialized octets as an owned sequence.
fn octets(value: &ByteBufferValue) -> Vec<u8> {
    value.octets().to_vec()
}

/// A split position beyond the initialized prefix, refused under every strategy.
fn refusal_of_split(value: &mut ByteBufferValue) -> String {
    let beyond = value.len().saturating_add(1);
    match value.split_off(beyond) {
        Ok(_) => panic!("a split beyond the prefix is refused"),
        Err(error) => format!("{:?}: {}", error.code(), error),
    }
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

#[test]
fn frozen_values_round_trip_identically_across_strategies() {
    let kind = ScalarKind::Signed(ScalarWidth::W32);
    let value = IntegerValue::new(kind, -7)
        .unwrap_or_else(|error| panic!("the integer is admitted: {error}"));
    let encoded = value.to_octets();
    let expected_text: String = encoded.iter().map(|octet| format!("{octet:02x}")).collect();
    let mut frozen = Vec::new();
    let mut losses = Vec::new();
    for strategy in StorageStrategy::ALL {
        let buffer = buffer(strategy, &encoded);
        let bytes = buffer
            .freeze()
            .unwrap_or_else(|error| panic!("an unshared buffer freezes: {error}"));
        let sealed: Vec<u8> = (0..bytes.len())
            .map(|index| bytes.octet(index))
            .collect::<Result<Vec<u8>, ScalarError>>()
            .unwrap_or_else(|error| panic!("every sealed octet is addressable: {error}"));
        assert_eq!(sealed, encoded, "external encoding identity");
        let text = bytes.to_canonical_text();
        assert_eq!(
            text, expected_text,
            "the canonical text is the exact lowercase hexadecimal spelling"
        );
        let reparsed = BytesValue::parse_canonical_text(&text)
            .unwrap_or_else(|error| panic!("the canonical text parses: {error}"));
        let recovered: Vec<u8> = (0..reparsed.len())
            .map(|index| reparsed.octet(index))
            .collect::<Result<Vec<u8>, ScalarError>>()
            .unwrap_or_else(|error| panic!("every reparsed octet is addressable: {error}"));
        assert_eq!(
            recovered, sealed,
            "the canonical text round-trips to this strategy's sealed octets"
        );
        assert_eq!(
            IntegerValue::from_octets(kind, &sealed)
                .unwrap_or_else(|error| panic!("the value round-trips: {error}"))
                .value(),
            -7,
            "the external encoding round-trips exactly"
        );
        // The width-loss projection is taken from this strategy's own sealed octets.
        let lossy = &sealed[..sealed.len() - 1];
        losses.push(refusal_of(IntegerValue::from_octets(kind, lossy)));
        frozen.push((sealed, text));
    }
    for pair in frozen.windows(2) {
        assert_eq!(pair[0].0, pair[1].0, "identical octets after freezing");
        assert_eq!(
            pair[0].1, pair[1].1,
            "identical canonical text after freezing"
        );
    }
    for fingerprint in &losses {
        assert_eq!(
            fingerprint, &losses[0],
            "a width-loss projection taken from any strategy's sealed octets is refused identically"
        );
    }
    assert!(
        !losses[0].is_empty(),
        "the width-loss projection is refused with a named diagnostic"
    );
}

#[test]
fn release_points_and_charge_conservation_are_identical_across_strategies() {
    let mut states = Vec::new();
    for strategy in StorageStrategy::ALL {
        let mut value = buffer(strategy, b"gantry-release");
        let charged = value.quota().used_octets();
        let mut tail = value
            .split_off(6)
            .unwrap_or_else(|error| panic!("the split position is inside the prefix: {error}"));
        assert_eq!(
            value.quota().used_octets() + tail.quota().used_octets(),
            charged,
            "splitting conserves the total charge"
        );
        let head_octets = octets(&value);
        let tail_octets = octets(&tail);
        assert_eq!(head_octets.len() + tail_octets.len(), charged);
        let released = tail.len();
        let tail_before = tail.quota().used_octets();
        assert_eq!(
            tail_before, released,
            "the split charges the tail its own octets"
        );
        tail.truncate(0)
            .unwrap_or_else(|error| panic!("truncating to zero is admitted: {error}"));
        assert_eq!(
            tail_before - tail.quota().used_octets(),
            released,
            "truncation releases exactly the removed octets"
        );
        assert_eq!(tail.quota().used_octets(), 0);
        let refusal = refusal_of_split(&mut value);
        states.push((
            head_octets,
            tail_octets,
            value.quota().used_octets(),
            tail.quota().used_octets(),
            released,
            tail_before,
            refusal,
        ));
    }
    for pair in states.windows(2) {
        assert_eq!(
            pair[0], pair[1],
            "identical octets, charges, releases, and refusals"
        );
    }
    assert!(states[0].4 > 0, "the differential exercised a real release");
}

/// The declared write accounting for a geometrically growing write sequence.
///
/// This pins the model's declared accounting against a tally the test keeps itself; it does not
/// measure an implementation and certifies no wall-clock or allocation behaviour.
#[test]
fn growing_write_chunks_charge_work_linear_in_the_data_handled() {
    const TARGET: usize = 4096;
    for strategy in StorageStrategy::ALL {
        let quota = ScalarQuota::charged(TARGET, 0)
            .unwrap_or_else(|error| panic!("the quota is admitted: {error}"));
        let mut value = ByteBufferValue::new(strategy, quota);
        let mut handled = 0_usize;
        let mut expected = 0_usize;
        let mut chunk = 1_usize;
        while handled < TARGET {
            let length = chunk.min(TARGET - handled);
            if matches!(strategy, StorageStrategy::CopyOnWrite) {
                expected += handled;
            }
            value
                .extend(&vec![0x2e_u8; length])
                .unwrap_or_else(|error| panic!("the chunk is admitted: {error}"));
            handled += length;
            chunk = chunk.saturating_mul(2);
        }
        assert_eq!(value.len(), TARGET);
        assert_eq!(
            value.physical_work(),
            expected,
            "the accumulated work matches the test's own tally of the declared rule"
        );
        assert!(
            expected == 0 || value.strategy().write_work(handled) > 0,
            "the per-step declaration agrees with the aggregate for a representative length"
        );
        assert!(
            expected <= 2 * handled,
            "geometric growth stays linear: {expected} <= {}",
            2 * handled
        );
    }
}
