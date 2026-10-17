//! Conformance for the bounded `std.env` launch-value model.
//!
//! The lane covers the value-only slice of `GNT-GP-ENV-001`: bounded immutable argument and
//! environment snapshots, explicit lookup and enumeration, update-as-new-snapshot, protected entry
//! handling, exact attenuated child projection, standalone/embedded injection parity, and durable
//! snapshot-versus-handle admission. It performs no host I/O and reads no ambient process state;
//! the only files it reads are the repository specification and the published model note.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    ArgumentSnapshot, ChildEnvironmentGrant, DurableEnvironmentRecord, ENV_DEFAULT_MAX_ARGUMENTS,
    ENV_DEFAULT_MAX_ENTRIES, ENV_DEFAULT_MAX_NAME_BYTES, ENV_DEFAULT_MAX_TOTAL_BYTES,
    ENV_DEFAULT_MAX_VALUE_BYTES, ENV_DURABLE_CARRIER, ENV_ITEMS, ENV_VALUE_CLAUSES,
    ENV_VALUE_CONTRACT_VERSION, EnvDiagnosticCode, EnvDurableCarrier, EnvError, EnvLimits,
    EnvironmentEntry, EnvironmentEntryName, EnvironmentSnapshot, EnvironmentValue,
    LaunchArrangement, ResourceCarrier, admit_durable_environment, admit_env_durable_carrier,
    admit_injection_parity, env_durable_carrier_is_admissible,
};

/// Returns the repository root from the conformance crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Reads one repository file, panicking with the path on failure.
fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Collapses every whitespace run so a published sentence can be pinned across line wrapping.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Returns the declared default bounds.
fn declared() -> EnvLimits {
    EnvLimits::declared()
}

/// Returns a small bound set used to reach every boundary cheaply.
fn tight() -> EnvLimits {
    EnvLimits::new(2, 3, 8, 16, 40)
        .unwrap_or_else(|error| panic!("the tight test bounds are valid: {error}"))
}

/// Admits one environment name or panics with the refusal.
fn name(value: &str, limits: &EnvLimits) -> EnvironmentEntryName {
    EnvironmentEntryName::new(value, limits)
        .unwrap_or_else(|error| panic!("environment name `{value}` is admitted: {error}"))
}

/// Admits one ordinary entry or panics with the refusal.
fn ordinary(limits: &EnvLimits, entry_name: &str, value: &str) -> EnvironmentEntry {
    EnvironmentEntry::ordinary(name(entry_name, limits), value, limits)
        .unwrap_or_else(|error| panic!("ordinary entry `{entry_name}` is admitted: {error}"))
}

/// Admits one protected entry or panics with the refusal.
fn protected(limits: &EnvLimits, entry_name: &str, value: &str) -> EnvironmentEntry {
    EnvironmentEntry::protected(name(entry_name, limits), value, limits)
        .unwrap_or_else(|error| panic!("protected entry `{entry_name}` is admitted: {error}"))
}

/// Admits one snapshot or panics with the refusal.
fn snapshot(entries: Vec<EnvironmentEntry>, limits: &EnvLimits) -> EnvironmentSnapshot {
    EnvironmentSnapshot::new(entries, limits)
        .unwrap_or_else(|error| panic!("the test snapshot is admitted: {error}"))
}

/// Returns the refusal code of a result that must be refused.
fn refusal<T>(result: Result<T, EnvError>) -> EnvDiagnosticCode {
    match result {
        Ok(_) => panic!("the presented value must be refused"),
        Err(error) => error.code(),
    }
}

/// The value contract publishes existing anchors, closed codes, and no new module row.
#[test]
fn env_value_contract_is_closed_and_publishes_no_new_module_row() {
    assert_eq!(
        ENV_VALUE_CLAUSES,
        [
            "GNT-30.2-bounded-launch-snapshot-and-capability-closure",
            "GNT-30.3-arguments-environment-and-logical-cwd",
            "GNT-49.0-environment-foundation-scope",
        ]
    );
    assert_eq!(ENV_VALUE_CONTRACT_VERSION, 1);
    assert_eq!(ENV_DEFAULT_MAX_ARGUMENTS, 4_096);
    assert_eq!(ENV_DEFAULT_MAX_ENTRIES, 4_096);
    assert_eq!(ENV_DEFAULT_MAX_NAME_BYTES, 256);
    assert_eq!(ENV_DEFAULT_MAX_VALUE_BYTES, 65_536);
    assert_eq!(ENV_DEFAULT_MAX_TOTAL_BYTES, 1_048_576);

    // The value model adds no `std.env` module row; that vocabulary is owned elsewhere.
    assert_eq!(ENV_ITEMS.len(), 3);

    let spellings = EnvDiagnosticCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(spellings.len(), EnvDiagnosticCode::ALL.len());
    assert!(
        EnvDiagnosticCode::ALL
            .iter()
            .all(|code| code.as_str().starts_with("env-"))
    );

    let specification = read_text(&workspace_root().join("SPEC.md"));
    for anchor in ENV_VALUE_CLAUSES {
        assert!(
            specification.contains(&format!("id=\"{anchor}\"")),
            "SPEC.md already anchors {anchor}"
        );
    }
}

/// Every declared bound is exact and nonzero; a zero bound admits no domain and is refused.
#[test]
fn env_limits_refuse_zero_bounds_and_expose_exact_values() {
    let bounds = declared();
    assert_eq!(bounds.max_arguments(), ENV_DEFAULT_MAX_ARGUMENTS);
    assert_eq!(bounds.max_entries(), ENV_DEFAULT_MAX_ENTRIES);
    assert_eq!(bounds.max_name_bytes(), ENV_DEFAULT_MAX_NAME_BYTES);
    assert_eq!(bounds.max_value_bytes(), ENV_DEFAULT_MAX_VALUE_BYTES);
    assert_eq!(bounds.max_total_bytes(), ENV_DEFAULT_MAX_TOTAL_BYTES);

    for index in 0..5 {
        let mut values = [4_096, 4_096, 256, 65_536, 1_048_576];
        values[index] = 0;
        let code = refusal(EnvLimits::new(
            values[0], values[1], values[2], values[3], values[4],
        ));
        assert_eq!(code, EnvDiagnosticCode::InvalidLimits);
    }

    let exact = EnvLimits::new(1, 1, 1, 1, 2)
        .unwrap_or_else(|error| panic!("nonzero bounds are admitted: {error}"));
    assert_eq!(exact.max_total_bytes(), 2);
}

/// Names and values admit only the declared portable domain and refuse malformed or oversize input.
#[test]
fn env_names_and_values_refuse_malformed_encodings() {
    let bounds = tight();
    assert_eq!(
        refusal(EnvironmentEntryName::new("", &bounds)),
        EnvDiagnosticCode::InvalidEntryName
    );
    assert_eq!(
        refusal(EnvironmentEntryName::new("A=B", &bounds)),
        EnvDiagnosticCode::InvalidEntryName
    );
    assert_eq!(
        refusal(EnvironmentEntryName::new("A\nB", &bounds)),
        EnvDiagnosticCode::InvalidEntryName
    );
    assert_eq!(
        refusal(EnvironmentEntryName::new("ABCDEFGHI", &bounds)),
        EnvDiagnosticCode::EntryByteBound
    );
    let boundary_name = EnvironmentEntryName::new("ABCDEFGH", &bounds)
        .unwrap_or_else(|error| panic!("the boundary name is admitted: {error}"));
    assert_eq!(boundary_name.as_str(), "ABCDEFGH");
    assert_eq!(
        refusal(EnvironmentEntryName::from_bytes(&[0xff], &bounds)),
        EnvDiagnosticCode::InvalidEncoding
    );
    assert_eq!(
        EnvDiagnosticCode::InvalidEntryName.as_str(),
        "env-invalid-entry-name"
    );

    assert_eq!(
        refusal(EnvironmentValue::ordinary("a\0b", &bounds)),
        EnvDiagnosticCode::InvalidValue
    );
    assert_eq!(
        refusal(EnvironmentValue::ordinary("x".repeat(17), &bounds)),
        EnvDiagnosticCode::EntryByteBound
    );
    assert_eq!(
        refusal(EnvironmentValue::from_bytes(
            &[0xff],
            gantry::ir::EnvProtection::Protected,
            &bounds
        )),
        EnvDiagnosticCode::InvalidEncoding
    );
    let boundary = EnvironmentValue::ordinary("x".repeat(16), &bounds)
        .unwrap_or_else(|error| panic!("the boundary value is admitted: {error}"));
    assert_eq!(boundary.byte_len(), 16);

    // The refusal detail names the condition without echoing the protected bytes.
    let secret = "secret-secret-secret";
    let error = match EnvironmentValue::protected(secret, &bounds) {
        Ok(_) => panic!("an oversize protected value must be refused"),
        Err(error) => error,
    };
    assert!(!error.detail().contains("secret"));
}

/// Duplicate names, count bounds, and total byte bounds each refuse exactly at the boundary.
#[test]
fn env_snapshot_refuses_duplicates_and_bounds() {
    let bounds = tight();
    let accepted = snapshot(
        vec![
            ordinary(&bounds, "A", "1"),
            ordinary(&bounds, "B", "2"),
            ordinary(&bounds, "C", "3"),
        ],
        &bounds,
    );
    assert_eq!(accepted.len(), 3);
    assert_eq!(accepted.total_bytes(), 6);

    assert_eq!(
        refusal(EnvironmentSnapshot::new(
            vec![ordinary(&bounds, "A", "1"), ordinary(&bounds, "A", "2"),],
            &bounds,
        )),
        EnvDiagnosticCode::DuplicateEntry
    );
    assert_eq!(
        refusal(EnvironmentSnapshot::new(
            vec![
                ordinary(&bounds, "A", ""),
                ordinary(&bounds, "B", ""),
                ordinary(&bounds, "C", ""),
                ordinary(&bounds, "D", ""),
            ],
            &bounds,
        )),
        EnvDiagnosticCode::EntryCountBound
    );
    // The count bound is checked before entry content, so an over-count presentation is never
    // indexed or payload-copied to discover a later per-entry refusal.
    assert_eq!(
        refusal(EnvironmentSnapshot::new(
            vec![
                ordinary(&bounds, "A", ""),
                ordinary(&bounds, "B", ""),
                ordinary(&bounds, "C", ""),
                ordinary(&declared(), "D", &"x".repeat(17)),
            ],
            &bounds,
        )),
        EnvDiagnosticCode::EntryCountBound
    );

    let total_bounds = EnvLimits::new(2, 10, 8, 16, 10)
        .unwrap_or_else(|error| panic!("the total-bound limits are valid: {error}"));
    let exact_total = snapshot(
        vec![
            ordinary(&total_bounds, "A", "1234"),
            ordinary(&total_bounds, "B", "1234"),
        ],
        &total_bounds,
    );
    assert_eq!(exact_total.total_bytes(), 10);
    assert_eq!(
        refusal(EnvironmentSnapshot::new(
            vec![
                ordinary(&total_bounds, "A", "1234"),
                ordinary(&total_bounds, "B", "1234"),
                ordinary(&total_bounds, "C", "1"),
            ],
            &total_bounds,
        )),
        EnvDiagnosticCode::TotalByteBound
    );
}

/// Lookup and enumeration are explicit, case-sensitive, and canonically ordered.
#[test]
fn env_lookup_and_enumeration_are_explicit_and_canonical() {
    let bounds = declared();
    let snapshot = snapshot(
        vec![
            ordinary(&bounds, "B", "two"),
            ordinary(&bounds, "A", "one"),
            ordinary(&bounds, "a", "lower"),
        ],
        &bounds,
    );

    let names = snapshot
        .iter()
        .map(|entry| entry.name().as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, ["A", "B", "a"]);
    assert_eq!(
        snapshot.get("A").map(|entry| entry.value().expose()),
        Some("one")
    );
    assert_eq!(
        snapshot.get("a").map(|entry| entry.value().expose()),
        Some("lower")
    );
    assert!(snapshot.contains("B"));
    assert!(!snapshot.contains("b"));
    assert!(snapshot.get("absent").is_none());
}

/// An update produces a new snapshot and never mutates the original or a sibling snapshot.
#[test]
fn env_updates_produce_new_snapshots_without_aliasing() {
    let bounds = tight();
    let base = snapshot(
        vec![ordinary(&bounds, "A", "1"), ordinary(&bounds, "B", "2")],
        &bounds,
    );

    let replaced = base
        .with_entry(ordinary(&bounds, "A", "9"))
        .unwrap_or_else(|error| panic!("the replacement is admitted: {error}"));
    assert_eq!(base.get("A").map(|entry| entry.value().expose()), Some("1"));
    assert_eq!(
        replaced.get("A").map(|entry| entry.value().expose()),
        Some("9")
    );
    assert_eq!(base.len(), 2);
    assert_eq!(replaced.len(), 2);
    assert_eq!(base.total_bytes(), 4);
    assert_eq!(replaced.total_bytes(), 4);

    let added = replaced
        .with_entry(ordinary(&bounds, "C", "3"))
        .unwrap_or_else(|error| panic!("the addition is admitted: {error}"));
    assert_eq!(added.len(), 3);
    assert_eq!(added.total_bytes(), 6);
    assert_eq!(replaced.len(), 2);

    let removed = added.without_entry("A");
    assert_eq!(removed.len(), 2);
    assert_eq!(removed.total_bytes(), 4);
    assert_eq!(added.len(), 3);
    assert_eq!(removed.without_entry("absent"), removed);

    // A fourth entry exceeds the declared count bound and leaves the sibling snapshots unchanged.
    assert_eq!(
        refusal(added.with_entry(ordinary(&bounds, "D", "4"))),
        EnvDiagnosticCode::EntryCountBound
    );
    assert_eq!(added.len(), 3);

    // An entry admitted under wider bounds is re-refused against this snapshot's exact bounds.
    let wider = declared();
    assert_eq!(
        refusal(added.with_entry(ordinary(&wider, "A", &"x".repeat(17)))),
        EnvDiagnosticCode::EntryByteBound
    );
    assert_eq!(
        added.get("A").map(|entry| entry.value().expose()),
        Some("9")
    );

    let sibling = replaced
        .with_entry(ordinary(&bounds, "D", "5"))
        .unwrap_or_else(|error| panic!("the sibling addition is admitted: {error}"));
    assert_eq!(sibling.len(), 3);
    assert_eq!(added.len(), 3);
    assert!(sibling.contains("D"));
    assert!(!added.contains("D"));
    assert!(!replaced.contains("D"));
}

/// Protected entries stay present but never appear in ordinary formatting.
#[test]
fn env_protected_entries_do_not_leak_through_ordinary_output() {
    let bounds = declared();
    let snapshot = snapshot(
        vec![
            ordinary(&bounds, "HOME", "/home/neil"),
            protected(&bounds, "API_TOKEN", "sekret-value"),
            ordinary(&bounds, "PASSWORD", "visible-pass"),
        ],
        &bounds,
    );

    let token = snapshot
        .get("API_TOKEN")
        .unwrap_or_else(|| panic!("the protected entry is present"));
    assert!(token.value().is_protected());
    assert_eq!(token.value().protection().wire_name(), "protected");
    assert_eq!(token.value().expose(), "sekret-value");
    assert!(!format!("{token}").contains("sekret-value"));
    assert!(format!("{token}").contains("<protected>"));
    assert!(!format!("{:?}", token.value()).contains("sekret-value"));
    assert!(!format!("{:?}", token).contains("sekret-value"));
    assert!(!format!("{snapshot:?}").contains("sekret-value"));

    // Protection is declared, never inferred from a suggestive name.
    let password = snapshot
        .get("PASSWORD")
        .unwrap_or_else(|| panic!("the ordinary entry is present"));
    assert!(!password.value().is_protected());
    assert!(format!("{password}").contains("visible-pass"));

    // Ordinary entries still render their exact value.
    let home = snapshot
        .get("HOME")
        .unwrap_or_else(|| panic!("the ordinary entry is present"));
    assert!(format!("{home}").contains("/home/neil"));
}

/// Child projection is exactly the explicit grant applied to the parent snapshot.
#[test]
fn env_child_projection_is_exact_attenuation() {
    let bounds = declared();
    let parent = snapshot(
        vec![
            ordinary(&bounds, "A", "one"),
            ordinary(&bounds, "B", "two"),
            protected(&bounds, "C", "child-secret"),
        ],
        &bounds,
    );

    let grant = ChildEnvironmentGrant::selecting(&["A", "C"], &bounds)
        .unwrap_or_else(|error| panic!("the subset grant is admitted: {error}"));
    let projection = parent.project_child(&grant);
    assert_eq!(projection.len(), 2);
    assert_eq!(
        projection
            .entries()
            .iter()
            .map(|entry| entry.name().as_str())
            .collect::<Vec<_>>(),
        ["A", "C"]
    );
    assert!(
        !projection
            .entries()
            .iter()
            .any(|entry| entry.name().as_str() == "B")
    );
    assert!(projection.is_subset_of(&parent));
    let child_secret = projection
        .entries()
        .iter()
        .find(|entry| entry.name().as_str() == "C")
        .unwrap_or_else(|| panic!("the protected grant is projected"));
    assert!(child_secret.value().is_protected());
    assert_eq!(child_secret.value().expose(), "child-secret");
    assert!(!format!("{child_secret:?}").contains("child-secret"));

    // An empty grant inherits nothing, and a grant never creates an absent entry.
    assert!(
        parent
            .project_child(&ChildEnvironmentGrant::empty())
            .is_empty()
    );
    let absent = ChildEnvironmentGrant::selecting(&["Z"], &bounds)
        .unwrap_or_else(|error| panic!("the absent-name grant is admitted: {error}"));
    assert!(parent.project_child(&absent).is_empty());

    // Projection is deterministic and never mutates the parent.
    assert_eq!(parent.project_child(&grant), projection);
    assert_eq!(parent.len(), 3);

    assert_eq!(
        refusal(ChildEnvironmentGrant::selecting(&["A", "A"], &bounds)),
        EnvDiagnosticCode::DuplicateEntry
    );
    assert_eq!(
        refusal(ChildEnvironmentGrant::selecting(&["A=B"], &bounds)),
        EnvDiagnosticCode::InvalidEntryName
    );
}

/// Standalone and embedded launches present one identical injection.
#[test]
fn env_injection_is_identical_for_standalone_and_embedded_launches() {
    let bounds = declared();
    let values = snapshot(
        vec![
            ordinary(&bounds, "A", "one"),
            protected(&bounds, "TOKEN", "launch-secret"),
        ],
        &bounds,
    );
    let arguments = ArgumentSnapshot::new(vec!["run".to_owned(), "--flag".to_owned()], &bounds)
        .unwrap_or_else(|error| panic!("the arguments are admitted: {error}"));
    let grant = ChildEnvironmentGrant::selecting(&["A", "TOKEN"], &bounds)
        .unwrap_or_else(|error| panic!("the injection grant is admitted: {error}"));

    let standalone = values.injection_plan(&arguments, &grant, LaunchArrangement::Standalone);
    let embedded = values.injection_plan(&arguments, &grant, LaunchArrangement::Embedded);
    assert_eq!(standalone.arrangement(), LaunchArrangement::Standalone);
    assert_eq!(embedded.arrangement(), LaunchArrangement::Embedded);
    assert_eq!(standalone.arguments(), ["run", "--flag"]);
    assert_eq!(standalone.arguments(), embedded.arguments());
    assert_eq!(standalone.environment(), embedded.environment());
    assert_eq!(admit_injection_parity(&standalone, &embedded), Ok(()));
    assert!(!format!("{standalone:?}").contains("launch-secret"));
    assert!(!format!("{embedded:?}").contains("launch-secret"));

    // A divergent value or a swapped arrangement is refused, not normalized away.
    let other = snapshot(
        vec![
            ordinary(&bounds, "A", "one"),
            protected(&bounds, "TOKEN", "other-secret"),
        ],
        &bounds,
    );
    let tampered = other.injection_plan(&arguments, &grant, LaunchArrangement::Embedded);
    assert_eq!(
        refusal(admit_injection_parity(&standalone, &tampered)),
        EnvDiagnosticCode::InjectionMismatch
    );
    assert_eq!(
        refusal(admit_injection_parity(&embedded, &standalone)),
        EnvDiagnosticCode::InjectionMismatch
    );
    assert_eq!(
        refusal(admit_injection_parity(&standalone, &standalone)),
        EnvDiagnosticCode::InjectionMismatch
    );
}

/// Argument snapshots preserve order and enforce their own count, byte, and total bounds.
#[test]
fn env_argument_snapshot_preserves_order_and_bounds() {
    let bounds = EnvLimits::new(2, 2, 8, 4, 6)
        .unwrap_or_else(|error| panic!("the argument limits are valid: {error}"));
    let accepted = ArgumentSnapshot::new(vec!["ab".to_owned(), "cd".to_owned()], &bounds)
        .unwrap_or_else(|error| panic!("the argument pair is admitted: {error}"));
    assert_eq!(accepted.len(), 2);
    assert_eq!(accepted.get(0), Some("ab"));
    assert_eq!(accepted.get(1), Some("cd"));
    assert_eq!(accepted.get(2), None);
    assert_eq!(accepted.iter().collect::<Vec<_>>(), ["ab", "cd"]);
    assert!(!accepted.is_empty());

    let empty = ArgumentSnapshot::new(Vec::new(), &bounds)
        .unwrap_or_else(|error| panic!("the empty argument list is admitted: {error}"));
    assert!(empty.is_empty());
    assert_eq!(empty.get(0), None);

    assert_eq!(
        refusal(ArgumentSnapshot::new(
            vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
            &bounds,
        )),
        EnvDiagnosticCode::ArgumentCountBound
    );
    assert_eq!(
        refusal(ArgumentSnapshot::new(vec!["abcde".to_owned()], &bounds)),
        EnvDiagnosticCode::ArgumentByteBound
    );
    assert_eq!(
        refusal(ArgumentSnapshot::new(vec!["a\0b".to_owned()], &bounds)),
        EnvDiagnosticCode::InvalidValue
    );
    assert_eq!(
        refusal(ArgumentSnapshot::new(
            vec!["abcd".to_owned(), "abc".to_owned()],
            &bounds,
        )),
        EnvDiagnosticCode::TotalByteBound
    );
}

/// A committed snapshot recovers exact values; handles and path/digest references grant nothing.
#[test]
fn env_durable_snapshot_recovers_but_handles_and_paths_do_not() {
    let bounds = declared();
    let original = snapshot(
        vec![
            ordinary(&bounds, "HOME", "/home/neil"),
            protected(&bounds, "API_TOKEN", "recovered-secret"),
        ],
        &bounds,
    );
    let record = original.durable_record();
    assert_eq!(record.version(), ENV_VALUE_CONTRACT_VERSION);
    assert_eq!(record.entries().len(), 2);

    let recovered = admit_durable_environment(&EnvDurableCarrier::CommittedSnapshot(Box::new(
        record.clone(),
    )))
    .unwrap_or_else(|error| panic!("the committed snapshot recovers: {error}"));
    assert_eq!(recovered, original);
    let token = recovered
        .get("API_TOKEN")
        .unwrap_or_else(|| panic!("the protected recovered entry is present"));
    assert!(token.value().is_protected());
    assert_eq!(token.value().expose(), "recovered-secret");
    assert!(!format!("{recovered:?}").contains("recovered-secret"));

    let decoded = DurableEnvironmentRecord::decode(1, record.entries().to_vec(), &bounds)
        .unwrap_or_else(|error| panic!("the durable record decodes: {error}"));
    assert_eq!(
        decoded
            .recover()
            .unwrap_or_else(|error| panic!("the decoded record recovers: {error}")),
        original
    );
    assert_eq!(
        refusal(DurableEnvironmentRecord::decode(
            2,
            record.entries().to_vec(),
            &bounds,
        )),
        EnvDiagnosticCode::IneligibleSnapshot
    );

    // A decoded record is stored in canonical ascending name order and is stable across recovery,
    // so decoded and re-recorded representations compare equal.
    let reversed = DurableEnvironmentRecord::decode(
        1,
        vec![ordinary(&bounds, "B", "2"), ordinary(&bounds, "A", "1")],
        &bounds,
    )
    .unwrap_or_else(|error| panic!("the reversed record decodes: {error}"));
    assert_eq!(
        reversed
            .entries()
            .iter()
            .map(|entry| entry.name().as_str())
            .collect::<Vec<_>>(),
        ["A", "B"]
    );
    let reversed_snapshot = reversed
        .recover()
        .unwrap_or_else(|error| panic!("the reversed record recovers: {error}"));
    assert_eq!(
        DurableEnvironmentRecord::committed(&reversed_snapshot),
        reversed
    );

    // Bounds are refused before payload indexing: the count bound wins over content, and an entry
    // admitted under wider bounds is re-refused by the record's narrower bound.
    let one_entry = EnvLimits::new(2, 1, 8, 16, 40)
        .unwrap_or_else(|error| panic!("the one-entry limits are valid: {error}"));
    assert_eq!(
        refusal(DurableEnvironmentRecord::decode(
            1,
            vec![ordinary(&bounds, "A", "1"), ordinary(&bounds, "B", "2")],
            &one_entry,
        )),
        EnvDiagnosticCode::EntryCountBound
    );
    assert_eq!(
        refusal(DurableEnvironmentRecord::decode(
            1,
            vec![ordinary(&bounds, "A", &"x".repeat(17))],
            &tight(),
        )),
        EnvDiagnosticCode::EntryByteBound
    );

    assert_eq!(
        refusal(admit_durable_environment(&EnvDurableCarrier::NativeHandle)),
        EnvDiagnosticCode::NativeHandleRefused
    );
    for reference in ["/run/gantry/env.snapshot", "sha256:0123456789abcdef"] {
        assert_eq!(
            refusal(admit_durable_environment(&EnvDurableCarrier::PathOrDigest(
                reference.to_owned()
            ))),
            EnvDiagnosticCode::PathDigestNoAuthority
        );
    }
    assert_eq!(
        EnvDurableCarrier::NativeHandle.carrier_name(),
        "native-handle"
    );
    assert_eq!(
        EnvDurableCarrier::PathOrDigest("x".to_owned()).carrier_name(),
        "path-or-digest"
    );

    assert_eq!(ENV_DURABLE_CARRIER, ResourceCarrier::ReconstructionRecord);
    assert!(env_durable_carrier_is_admissible(
        ResourceCarrier::ReconstructionRecord
    ));
    for carrier in [
        ResourceCarrier::OrdinarySerialization,
        ResourceCarrier::OrdinaryDurableState,
    ] {
        assert!(!env_durable_carrier_is_admissible(carrier));
        assert_eq!(
            refusal(admit_env_durable_carrier(carrier)),
            EnvDiagnosticCode::IneligibleSnapshot
        );
    }

    // A recovered snapshot still attenuates exactly and preserves protection.
    let grant = ChildEnvironmentGrant::selecting(&["API_TOKEN"], &bounds)
        .unwrap_or_else(|error| panic!("the recovered grant is admitted: {error}"));
    let projection = recovered.project_child(&grant);
    assert_eq!(projection.len(), 1);
    assert!(projection.is_subset_of(&recovered));
    assert!(
        projection.entries()[0].value().is_protected(),
        "protection survives recovery"
    );

    // A malformed durable record recovers nothing.
    let duplicate = vec![ordinary(&bounds, "A", "1"), ordinary(&bounds, "A", "2")];
    assert_eq!(
        refusal(DurableEnvironmentRecord::decode(1, duplicate, &bounds)),
        EnvDiagnosticCode::DuplicateEntry
    );
}

/// The published model note states the landed value contract and its non-claims.
#[test]
fn env_value_note_publishes_the_value_contract_boundaries() {
    let note = flatten(&read_text(
        &workspace_root().join("docs/env-value-snapshots.md"),
    ));
    for anchor in ENV_VALUE_CLAUSES {
        assert!(note.contains(anchor), "the note must cite {anchor}");
    }
    for phrase in [
        "bounded immutable argument and environment snapshots",
        "explicit lookup and enumeration",
        "update produces a new snapshot",
        "protected entries are present in the exact snapshot",
        "attenuated child projection",
        "standalone and embedded injection",
        "native handle never resurrects",
        "path or digest grants no authority",
        "no ambient process read",
        "crates/gantry-conformance/tests/env_value_snapshots.rs",
    ] {
        assert!(
            note.to_lowercase().contains(&phrase.to_lowercase()),
            "the note must state: {phrase}"
        );
    }
}
