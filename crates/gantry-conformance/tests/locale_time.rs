//! Machine-checked conformance for the pure Section 33 locale and civil-time model.
//!
//! The tests use declared machine formats, locale values, civil-time values, pinned
//! rule data, disambiguations, snapshots, and availability facts only. They neither
//! read a host locale or time zone, consult an installed database, observe a clock,
//! nor create runtime or durable state.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    CalendarIdentity, CivilResolution, CivilValue, CollationIdentity, Deadline, Disambiguation,
    DurableTemporalRecord, Duration, Instant, LOCALE_CLAUSES, LOCALE_NON_CLAIM_ORDER,
    LOCALE_NON_CLAIMS, LocaleDiagnosticCode, LocaleError, LocaleNonClaim, LocaleNonClaimAssertion,
    LocaleValue, MAX_CIVIL_YEAR, MAX_DURATION_SECONDS, MAX_LOCALE_IDENTIFIER_BYTES,
    MAX_OFFSET_SECONDS, MAX_PRESENTATION_TEXT_BYTES, MIN_CIVIL_YEAR, MachineFormat, Offset,
    PreferenceOrigin, PreferenceSnapshot, PresentationText, RuleData, RuleDataArtifactBinding,
    RuleDataBinding, RuleDataKind, RuleDataUpgrade, TargetDataAvailability, TargetKind,
    ZoneTransition, check_locale_non_claims, classify_civil, require_rule_data_available,
    require_superseded_refused, resolve_civil,
};

/// The local seconds of `1970-01-02T00:00:00`, the fixture civil time.
const BASE_LOCAL: i64 = 86_400;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance crate has a workspace parent"))
        .to_path_buf()
}

/// Returns the refusal produced by one rejected locale decision.
fn refuse<T>(outcome: Result<T, LocaleError>, context: &str) -> LocaleError {
    match outcome {
        Ok(_) => panic!("{context}: the decision must be refused"),
        Err(error) => error,
    }
}

fn civil(year: i64, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> CivilValue {
    CivilValue::new(
        CalendarIdentity::ProlepticGregorian,
        year,
        month,
        day,
        hour,
        minute,
        second,
    )
    .unwrap_or_else(|error| panic!("the fixture civil value is valid: {error}"))
}

fn base_civil() -> CivilValue {
    civil(1970, 1, 2, 0, 0, 0)
}

fn offset(seconds: i32) -> Offset {
    Offset::new(seconds).unwrap_or_else(|error| panic!("the fixture offset is bounded: {error}"))
}

fn transition(at_seconds: i64, offset_seconds: i32) -> ZoneTransition {
    ZoneTransition::new(at_seconds, offset(offset_seconds))
        .unwrap_or_else(|error| panic!("the fixture transition is valid: {error}"))
}

fn zone(transitions: &[ZoneTransition], version: &str) -> RuleData {
    RuleData::new(
        RuleDataKind::Zone,
        "Zone/Test",
        version,
        transitions,
        &["standard-offset", "summer-offset"],
    )
    .unwrap_or_else(|error| panic!("the fixture zone rule data is valid: {error}"))
}

fn unique_zone() -> RuleData {
    zone(
        &[
            transition(0, 3_600),
            transition(BASE_LOCAL + 100_000, 7_200),
        ],
        "2024a",
    )
}

fn gap_zone() -> RuleData {
    zone(
        &[transition(0, 3_600), transition(BASE_LOCAL - 3_600, 7_200)],
        "2024a",
    )
}

fn repetition_zone() -> RuleData {
    zone(
        &[transition(0, 7_200), transition(BASE_LOCAL - 3_600, 3_600)],
        "2024a",
    )
}

fn locale() -> LocaleValue {
    LocaleValue::new("en-GB", "cldr-44", CollationIdentity::UnicodeDefault)
        .unwrap_or_else(|error| panic!("the fixture locale value is valid: {error}"))
}

#[test]
fn section_33_anchors_and_closed_vocabularies_are_published() {
    assert_eq!(LOCALE_CLAUSES.len(), 13);
    let specification = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"));
    for clause in LOCALE_CLAUSES {
        assert!(
            specification.contains(&format!("<a id=\"{clause}\"></a>")),
            "Section 33 must publish {clause}"
        );
    }
    for format in MachineFormat::ALL {
        assert_eq!(
            MachineFormat::from_wire_name(format.wire_name()),
            Some(format)
        );
    }
    assert_eq!(MachineFormat::ALL.len(), 4);
    for identity in CollationIdentity::ALL {
        assert_eq!(
            CollationIdentity::from_wire_name(identity.wire_name()),
            Some(identity)
        );
    }
    for identity in CalendarIdentity::ALL {
        assert_eq!(
            CalendarIdentity::from_wire_name(identity.wire_name()),
            Some(identity)
        );
    }
    for kind in RuleDataKind::ALL {
        assert_eq!(RuleDataKind::from_wire_name(kind.wire_name()), Some(kind));
    }
    for declaration in Disambiguation::ALL {
        assert_eq!(
            Disambiguation::from_wire_name(declaration.wire_name()),
            Some(declaration)
        );
    }
    for origin in PreferenceOrigin::ALL {
        assert_eq!(
            PreferenceOrigin::from_wire_name(origin.wire_name()),
            Some(origin)
        );
    }
    let spellings = LocaleDiagnosticCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<Vec<&str>>();
    let mut sorted = spellings.clone();
    sorted.sort_unstable();
    assert_eq!(
        spellings, sorted,
        "the frozen diagnostic registry is in canonical spelling order"
    );
    for code in LocaleDiagnosticCode::ALL {
        assert_eq!(
            LocaleDiagnosticCode::from_wire_name(code.as_str()),
            Some(code)
        );
        assert!(LOCALE_CLAUSES.contains(&code.requirement()));
        assert!(
            specification.contains(code.as_str()),
            "Section 33 must publish the frozen spelling {}",
            code.as_str()
        );
    }
    assert_eq!(LOCALE_NON_CLAIMS.len(), LocaleNonClaim::ALL.len());
}

#[test]
fn machine_formats_round_trip_and_refuse_noncanonical_spellings() {
    let instant = Instant::parse("1970-01-01T00:00:00.000000Z")
        .unwrap_or_else(|error| panic!("the canonical instant parses: {error}"));
    assert_eq!(instant.seconds(), 0);
    assert_eq!(instant.to_canonical_string(), "1970-01-01T00:00:00.000000Z");
    assert_eq!(
        instant.canonical().to_string(),
        instant.to_canonical_string()
    );
    assert_eq!(
        Instant::from_seconds(BASE_LOCAL).map(|value| value.seconds()),
        Ok(BASE_LOCAL)
    );
    for spelling in [
        "1970-01-01T00:00:00Z",
        "1970-01-01",
        "1970-01-01 00:00:00.000000Z",
        "1970-13-01T00:00:00.000000Z",
    ] {
        let error = refuse(Instant::parse(spelling), "a noncanonical instant spelling");
        assert_eq!(error.code(), LocaleDiagnosticCode::InvalidMachineFormat);
        assert_eq!(error.requirement(), LOCALE_CLAUSES[1]);
    }
    assert_eq!(Duration::new(-5).map(Duration::seconds), Ok(-5));
    assert_eq!(Duration::new(0).map(Duration::seconds), Ok(0));
    assert_eq!(
        Duration::new(MAX_DURATION_SECONDS).map(Duration::seconds),
        Ok(MAX_DURATION_SECONDS)
    );
    assert_eq!(
        refuse(
            Duration::new(MAX_DURATION_SECONDS + 1),
            "an out-of-bound duration"
        )
        .code(),
        LocaleDiagnosticCode::InvalidMachineFormat
    );
    for (text, seconds) in [("123s", 123), ("-5s", -5), ("0s", 0)] {
        let parsed = Duration::parse(text)
            .unwrap_or_else(|error| panic!("the canonical duration {text} parses: {error}"));
        assert_eq!(parsed.seconds(), seconds);
        assert_eq!(parsed.to_canonical_string(), text);
    }
    for text in ["123", "1.5s", "s", "12s3", "+7s", "007s", "-0s", "+0s"] {
        assert_eq!(
            refuse(Duration::parse(text), "a noncanonical duration").code(),
            LocaleDiagnosticCode::InvalidMachineFormat
        );
    }
    for (text, seconds) in [
        ("+01:00:00", 3_600),
        ("-05:30:00", -19_800),
        ("+00:00:00", 0),
        ("+00:00:30", 30),
        ("+00:01:30", 90),
        ("+00:59:59", 3_599),
        ("-00:00:30", -30),
        ("-00:01:30", -90),
        ("-00:59:59", -3_599),
    ] {
        let parsed = Offset::parse(text)
            .unwrap_or_else(|error| panic!("the canonical offset {text} parses: {error}"));
        assert_eq!(parsed.seconds(), seconds);
        assert_eq!(parsed.to_canonical_string(), text);
    }
    for text in [
        "1:00",
        "+1:00",
        "+01:60",
        "0100",
        "+01:00",
        "-00:00:00",
        "+01:00:60",
        "01:00:00",
    ] {
        assert_eq!(
            refuse(Offset::parse(text), "a noncanonical offset").code(),
            LocaleDiagnosticCode::InvalidMachineFormat
        );
    }
    for (text, fields) in [
        ("1970-01-02T00:00:00", (1970, 1, 2, 0, 0, 0)),
        ("2024-02-29T23:59:59", (2024, 2, 29, 23, 59, 59)),
    ] {
        let parsed = CivilValue::parse(text)
            .unwrap_or_else(|error| panic!("the canonical civil value {text} parses: {error}"));
        assert_eq!(parsed.fields(), fields);
        assert_eq!(parsed.to_canonical_string(), text);
    }
    for text in [
        "1970-01-02 00:00:00",
        "1970-01-02T00:00",
        "1970-01-02T00:00:00Z",
    ] {
        assert_eq!(
            refuse(CivilValue::parse(text), "a noncanonical civil value").code(),
            LocaleDiagnosticCode::InvalidMachineFormat
        );
    }
    // A canonical-shaped text whose fields are out of bounds reports the field-bound
    // diagnostic, while a text the canonical format does not admit reports the
    // machine-format diagnostic.
    assert_eq!(
        refuse(
            CivilValue::parse("1970-02-30T00:00:00"),
            "a canonical-shaped civil text with an out-of-bound field"
        )
        .code(),
        LocaleDiagnosticCode::InvalidCivilValue
    );
}

#[test]
fn locale_values_require_explicit_bounded_identities() {
    let value = locale();
    assert_eq!(value.identifier(), "en-GB");
    assert_eq!(value.data_version(), "cldr-44");
    assert_eq!(value.collation(), CollationIdentity::UnicodeDefault);
    assert_eq!(value, locale());
    for (identifier, data_version) in [
        ("", "cldr-44"),
        ("en GB", "cldr-44"),
        ("en-GB", ""),
        ("en-GB", "   "),
    ] {
        let error = refuse(
            LocaleValue::new(identifier, data_version, CollationIdentity::Binary),
            "a malformed locale value",
        );
        assert_eq!(error.code(), LocaleDiagnosticCode::InvalidLocaleIdentity);
        assert_eq!(error.requirement(), LOCALE_CLAUSES[2]);
    }
    let oversized = "a".repeat(MAX_LOCALE_IDENTIFIER_BYTES + 1);
    assert_eq!(
        refuse(
            LocaleValue::new(oversized.as_str(), "cldr-44", CollationIdentity::Binary),
            "an oversized locale identifier"
        )
        .code(),
        LocaleDiagnosticCode::InvalidLocaleIdentity
    );
    assert_eq!(
        CollationIdentity::admit("binary").ok(),
        Some(CollationIdentity::Binary)
    );
    assert_eq!(
        refuse(
            CollationIdentity::admit("custom"),
            "an undeclared collation"
        )
        .code(),
        LocaleDiagnosticCode::InvalidLocaleIdentity
    );
    assert_eq!(
        CalendarIdentity::admit("proleptic-gregorian").ok(),
        Some(CalendarIdentity::ProlepticGregorian)
    );
    assert_eq!(
        refuse(CalendarIdentity::admit("julian"), "an undeclared calendar").code(),
        LocaleDiagnosticCode::InvalidCivilValue
    );
}

#[test]
fn civil_values_are_bounds_checked_not_normalized() {
    let value = base_civil();
    assert_eq!(value.fields(), (1970, 1, 2, 0, 0, 0));
    assert_eq!(value.local_seconds(), BASE_LOCAL);
    assert_eq!(value.calendar(), CalendarIdentity::ProlepticGregorian);
    let leap = civil(1972, 2, 29, 23, 59, 59);
    assert_eq!(leap.fields(), (1972, 2, 29, 23, 59, 59));
    for (year, month, day, hour, minute, second) in [
        (MIN_CIVIL_YEAR - 1, 1, 1, 0, 0, 0),
        (MAX_CIVIL_YEAR + 1, 1, 1, 0, 0, 0),
        (100_000_000_000_000_000, 1, 1, 0, 0, 0),
        (1970, 2, 29, 0, 0, 0),
        (1970, 0, 1, 0, 0, 0),
        (1970, 13, 1, 0, 0, 0),
        (1970, 1, 0, 0, 0, 0),
        (1970, 4, 31, 0, 0, 0),
        (1970, 1, 1, 24, 0, 0),
        (1970, 1, 1, 0, 60, 0),
        (1970, 1, 1, 0, 0, 60),
    ] {
        let error = refuse(
            CivilValue::new(
                CalendarIdentity::ProlepticGregorian,
                year,
                month,
                day,
                hour,
                minute,
                second,
            ),
            "an out-of-bound civil field",
        );
        assert_eq!(error.code(), LocaleDiagnosticCode::InvalidCivilValue);
        assert_eq!(error.requirement(), LOCALE_CLAUSES[3]);
    }
}

#[test]
fn offsets_are_bounded_to_the_declared_range() {
    assert_eq!(Offset::new(0).map(Offset::seconds), Ok(0));
    assert_eq!(offset(MAX_OFFSET_SECONDS).seconds(), MAX_OFFSET_SECONDS);
    assert_eq!(offset(-MAX_OFFSET_SECONDS).seconds(), -MAX_OFFSET_SECONDS);
    for seconds in [MAX_OFFSET_SECONDS + 1, -MAX_OFFSET_SECONDS - 1] {
        let error = refuse(Offset::new(seconds), "an out-of-bound offset");
        assert_eq!(error.code(), LocaleDiagnosticCode::InvalidCivilValue);
    }
}

#[test]
fn civil_classification_reports_unique_gap_and_repetition() {
    let unique = classify_civil(base_civil(), &unique_zone())
        .unwrap_or_else(|error| panic!("the unique classification is computed: {error}"));
    assert_eq!(unique.wire_name(), "unique");
    match unique {
        CivilResolution::Unique { instant } => assert_eq!(instant.seconds(), BASE_LOCAL - 3_600),
        other => panic!("expected a unique classification, got {other:?}"),
    }
    match classify_civil(base_civil(), &gap_zone())
        .unwrap_or_else(|error| panic!("the gap classification is computed: {error}"))
    {
        CivilResolution::Gap { gap_seconds } => assert_eq!(gap_seconds, 3_600),
        other => panic!("expected a gap classification, got {other:?}"),
    }
    match classify_civil(base_civil(), &repetition_zone())
        .unwrap_or_else(|error| panic!("the repetition classification is computed: {error}"))
    {
        resolution @ CivilResolution::Repetition { .. } => {
            let candidates = resolution.candidates();
            assert_eq!(
                candidates.len(),
                2,
                "the fixture repetition names two instants"
            );
            assert_eq!(candidates[0].seconds(), BASE_LOCAL - 7_200);
            assert_eq!(candidates[1].seconds(), BASE_LOCAL - 3_600);
        }
        other => panic!("expected a repetition classification, got {other:?}"),
    }
    match classify_civil(base_civil(), &zone(&[transition(0, 3_600)], "2024a"))
        .unwrap_or_else(|error| panic!("the baseline-offset classification is computed: {error}"))
    {
        CivilResolution::Unique { instant } => assert_eq!(instant.seconds(), BASE_LOCAL - 3_600),
        other => panic!("a single declared offset classifies as unique, got {other:?}"),
    }
    assert_eq!(
        refuse(
            classify_civil(
                base_civil(),
                &RuleData::new(
                    RuleDataKind::Locale,
                    "Locale/Test",
                    "cldr-44",
                    &[],
                    &["syntax"]
                )
                .unwrap_or_else(|error| panic!("the fixture locale rule data is valid: {error}"))
            ),
            "classification against locale rule data"
        )
        .code(),
        LocaleDiagnosticCode::InvalidCivilValue
    );
}

#[test]
fn multi_fold_data_keeps_every_candidate_instant() {
    // Three declared offsets map this civil time, so the classification must retain
    // every candidate and prefer-later must return the latest one rather than the
    // second, which a two-slot representation would silently drop.
    let rules = zone(
        &[
            transition(-10_000, 7_200),
            transition(-5_000, 3_600),
            transition(-1_000, 0),
        ],
        "2024a",
    );
    let value = civil(1970, 1, 1, 0, 0, 0);
    let resolution = classify_civil(value, &rules)
        .unwrap_or_else(|error| panic!("the multi-fold classification is computed: {error}"));
    let candidates = resolution.candidates();
    assert_eq!(candidates.len(), 3, "every valid mapping is retained");
    assert_eq!(candidates[0].seconds(), -7_200);
    assert_eq!(candidates[2].seconds(), 0);
    assert_eq!(
        resolve_civil(value, &rules, Some(Disambiguation::PreferEarlier))
            .map(|instant| instant.seconds()),
        Ok(-7_200)
    );
    assert_eq!(
        resolve_civil(value, &rules, Some(Disambiguation::PreferLater))
            .map(|instant| instant.seconds()),
        Ok(0),
        "prefer-later returns the latest candidate rather than the second"
    );
    assert_eq!(
        refuse(
            resolve_civil(value, &rules, Some(Disambiguation::Reject)),
            "a rejected multi-fold civil time"
        )
        .code(),
        LocaleDiagnosticCode::AmbiguousCivilTime
    );
}

#[test]
fn rule_data_identity_binds_artifacts_and_recovery() {
    let rules = unique_zone();
    let identity = rules.identity();
    let library =
        RuleDataArtifactBinding::new(TargetKind::Library, std::slice::from_ref(&identity));
    let binary = RuleDataArtifactBinding::new(TargetKind::Binary, std::slice::from_ref(&identity));
    assert_eq!(library.target(), TargetKind::Library);
    assert_eq!(library.identities().len(), 1);
    assert_ne!(
        library.identity().as_str(),
        binary.identity().as_str(),
        "the declared target participates in the artifact identity"
    );
    let changed = RuleDataArtifactBinding::new(
        TargetKind::Library,
        &[zone(rules.transitions(), "2024b").identity()],
    );
    assert_ne!(
        library.identity().as_str(),
        changed.identity().as_str(),
        "a pinned rule-data identity participates in the artifact identity"
    );
    let observation = Instant::from_seconds(BASE_LOCAL)
        .unwrap_or_else(|error| panic!("the fixture instant is valid: {error}"));
    let rejected = DurableTemporalRecord::new(
        identity.clone(),
        observation.clone(),
        Some(locale()),
        Disambiguation::Reject,
    );
    let preferred = DurableTemporalRecord::new(
        identity,
        observation,
        Some(locale()),
        Disambiguation::PreferLater,
    );
    assert_eq!(rejected.disambiguation(), Disambiguation::Reject);
    assert_ne!(
        rejected.recovery_identity().as_str(),
        preferred.recovery_identity().as_str(),
        "the retained disambiguation participates in the recovery identity"
    );
}

#[test]
fn resolution_requires_an_explicit_disambiguation() {
    assert_eq!(
        resolve_civil(base_civil(), &unique_zone(), None).map(|instant| instant.seconds()),
        Ok(BASE_LOCAL - 3_600),
        "a unique civil time resolves without a declaration"
    );
    for (rules, context) in [
        (gap_zone(), "a nonexistent civil time"),
        (repetition_zone(), "a repeated civil time"),
    ] {
        let error = refuse(resolve_civil(base_civil(), &rules, None), context);
        assert_eq!(error.code(), LocaleDiagnosticCode::MissingDisambiguation);
        assert_eq!(error.requirement(), LOCALE_CLAUSES[4]);
    }
}

#[test]
fn rejection_refuses_gap_and_repetition() {
    assert_eq!(
        refuse(
            resolve_civil(base_civil(), &gap_zone(), Some(Disambiguation::Reject)),
            "a rejected gap"
        )
        .code(),
        LocaleDiagnosticCode::NonexistentCivilTime
    );
    assert_eq!(
        refuse(
            resolve_civil(
                base_civil(),
                &repetition_zone(),
                Some(Disambiguation::Reject)
            ),
            "a rejected repetition"
        )
        .code(),
        LocaleDiagnosticCode::AmbiguousCivilTime
    );
    assert_eq!(
        resolve_civil(
            base_civil(),
            &gap_zone(),
            Some(Disambiguation::PreferEarlier)
        )
        .map(|instant| instant.seconds()),
        Ok(BASE_LOCAL - 3_600)
    );
    assert_eq!(
        resolve_civil(base_civil(), &gap_zone(), Some(Disambiguation::PreferLater))
            .map(|instant| instant.seconds()),
        Ok(BASE_LOCAL - 7_200)
    );
    assert_eq!(
        resolve_civil(
            base_civil(),
            &repetition_zone(),
            Some(Disambiguation::PreferEarlier)
        )
        .map(|instant| instant.seconds()),
        Ok(BASE_LOCAL - 7_200)
    );
    assert_eq!(
        resolve_civil(
            base_civil(),
            &repetition_zone(),
            Some(Disambiguation::PreferLater)
        )
        .map(|instant| instant.seconds()),
        Ok(BASE_LOCAL - 3_600)
    );
    // The declarations select the earlier or the later declared UTC offset, so the
    // two classifications order inversely: across a gap the earlier offset names the
    // later instant, while across a repetition it names the earlier instant.
    let gap_earlier_offset = resolve_civil(
        base_civil(),
        &gap_zone(),
        Some(Disambiguation::PreferEarlier),
    )
    .map(|instant| instant.seconds())
    .unwrap_or_else(|error| panic!("the gap resolves: {error}"));
    let gap_later_offset =
        resolve_civil(base_civil(), &gap_zone(), Some(Disambiguation::PreferLater))
            .map(|instant| instant.seconds())
            .unwrap_or_else(|error| panic!("the gap resolves: {error}"));
    assert!(
        gap_earlier_offset > gap_later_offset,
        "across a gap the earlier declared offset names the later instant"
    );
    let repeated_earlier_offset = resolve_civil(
        base_civil(),
        &repetition_zone(),
        Some(Disambiguation::PreferEarlier),
    )
    .map(|instant| instant.seconds())
    .unwrap_or_else(|error| panic!("the repetition resolves: {error}"));
    let repeated_later_offset = resolve_civil(
        base_civil(),
        &repetition_zone(),
        Some(Disambiguation::PreferLater),
    )
    .map(|instant| instant.seconds())
    .unwrap_or_else(|error| panic!("the repetition resolves: {error}"));
    assert!(
        repeated_earlier_offset < repeated_later_offset,
        "across a repetition the earlier declared offset names the earlier instant"
    );
}

#[test]
fn rule_data_identity_covers_every_declared_fact() {
    let base = unique_zone();
    assert_eq!(base.identity(), unique_zone().identity());
    assert_eq!(base.kind(), RuleDataKind::Zone);
    assert_eq!(base.identifier(), "Zone/Test");
    assert_eq!(base.version(), "2024a");
    assert_eq!(base.transitions().len(), 2);
    assert!(base.facts().contains("standard-offset"));
    assert_ne!(
        base.identity(),
        zone(base.transitions(), "2024b").identity()
    );
    assert_ne!(
        base.identity(),
        zone(
            &[
                transition(0, 3_600),
                transition(BASE_LOCAL + 100_000, 3_600)
            ],
            "2024a"
        )
        .identity()
    );
    assert_ne!(
        base.identity(),
        RuleData::new(
            RuleDataKind::Zone,
            "Zone/Other",
            "2024a",
            base.transitions(),
            &["standard-offset", "summer-offset"]
        )
        .unwrap_or_else(|error| panic!("the fixture zone is valid: {error}"))
        .identity()
    );
    assert_ne!(
        base.identity(),
        RuleData::new(
            RuleDataKind::Zone,
            "Zone/Test",
            "2024a",
            base.transitions(),
            &["standard-offset"]
        )
        .unwrap_or_else(|error| panic!("the fixture zone is valid: {error}"))
        .identity()
    );
    assert_eq!(
        refuse(
            RuleData::new(RuleDataKind::Zone, "Zone/Test", "2024a", &[], &[]),
            "zone rule data without transitions"
        )
        .code(),
        LocaleDiagnosticCode::InvalidCivilValue
    );
    assert_eq!(
        refuse(
            RuleData::new(
                RuleDataKind::Locale,
                "Locale/Test",
                "cldr-44",
                base.transitions(),
                &[]
            ),
            "transitions on non-zone rule data"
        )
        .code(),
        LocaleDiagnosticCode::InvalidCivilValue
    );
    assert_eq!(
        refuse(
            RuleData::new(
                RuleDataKind::Zone,
                "Zone/Test",
                "2024a",
                &[transition(BASE_LOCAL, 3_600), transition(0, 7_200)],
                &[]
            ),
            "unordered zone transitions"
        )
        .code(),
        LocaleDiagnosticCode::InvalidCivilValue
    );
}

#[test]
fn rule_data_binding_refuses_a_different_presented_identity() {
    let rules = unique_zone();
    let pin = rules.identity();
    assert!(
        RuleDataBinding::new(pin.clone(), pin.clone())
            .verify()
            .is_ok()
    );
    let other = zone(rules.transitions(), "2024b").identity();
    let error = refuse(
        RuleDataBinding::new(pin, other).verify(),
        "a presented rule-data identity that differs from the pin",
    );
    assert_eq!(error.code(), LocaleDiagnosticCode::RuleDataIdentityMismatch);
    assert_eq!(error.requirement(), LOCALE_CLAUSES[5]);
}

#[test]
fn preference_snapshots_refuse_ambient_reads() {
    assert_eq!(
        refuse(
            PreferenceSnapshot::new(Some(locale()), None, PreferenceOrigin::AmbientHost),
            "an ambient host preference"
        )
        .code(),
        LocaleDiagnosticCode::AmbientPreference
    );
    let snapshot = PreferenceSnapshot::new(
        Some(locale()),
        Some(unique_zone().identity()),
        PreferenceOrigin::EntrySnapshot,
    )
    .unwrap_or_else(|error| panic!("the fixture snapshot is valid: {error}"));
    assert_eq!(snapshot.origin(), PreferenceOrigin::EntrySnapshot);
    assert_eq!(snapshot.locale(), Some(&locale()));
    assert!(snapshot.zone().is_some());
    assert!(
        !snapshot.is_implicitly_reread(),
        "a snapshot is never re-read implicitly"
    );
    let changed = PreferenceSnapshot::new(
        Some(
            LocaleValue::new("fr-FR", "cldr-44", CollationIdentity::UnicodeDefault)
                .unwrap_or_else(|error| panic!("the fixture locale is valid: {error}")),
        ),
        snapshot.zone().cloned(),
        PreferenceOrigin::VisibleOperation,
    )
    .unwrap_or_else(|error| panic!("the changed snapshot is valid: {error}"));
    assert_ne!(
        snapshot, changed,
        "a preference change is a new snapshot value"
    );
}

#[test]
fn target_availability_rejects_undeclared_data() {
    let rules = unique_zone();
    let other = zone(rules.transitions(), "2024b");
    let availability = TargetDataAvailability::new(TargetKind::Library, &[rules.identity()]);
    assert_eq!(availability.target(), TargetKind::Library);
    assert!(availability.require(&rules.identity()).is_ok());
    assert_eq!(availability.identities().len(), 1);
    let error = refuse(
        availability.require(&other.identity()),
        "an undeclared data identity",
    );
    assert_eq!(error.code(), LocaleDiagnosticCode::UnsupportedLocaleData);
    assert_eq!(error.requirement(), LOCALE_CLAUSES[7]);
}

#[test]
fn presentation_text_is_never_value_authority() {
    let text = PresentationText::new(&locale(), "2 January 1970")
        .unwrap_or_else(|error| panic!("the fixture presentation text is valid: {error}"));
    assert_eq!(text.text(), "2 January 1970");
    assert_eq!(text.locale(), &locale());
    assert_eq!(
        refuse(
            text.as_value_authority(),
            "presentation text as value authority"
        )
        .code(),
        LocaleDiagnosticCode::PresentationNotAuthority
    );
    let oversized = "x".repeat(MAX_PRESENTATION_TEXT_BYTES + 1);
    assert_eq!(
        refuse(
            PresentationText::new(&locale(), oversized.as_str()),
            "oversized presentation text"
        )
        .code(),
        LocaleDiagnosticCode::PresentationNotAuthority
    );
}

#[test]
fn deadlines_are_monotonic_and_refuse_wall_values() {
    assert_eq!(Deadline::from_monotonic(10).ticks(), 10);
    let instant = Instant::from_seconds(BASE_LOCAL)
        .unwrap_or_else(|error| panic!("the fixture instant is valid: {error}"));
    let error = refuse(Deadline::from_wall(&instant), "a wall-clock deadline");
    assert_eq!(error.code(), LocaleDiagnosticCode::HostConsultationRefused);
    assert_eq!(error.requirement(), LOCALE_CLAUSES[9]);
}

#[test]
fn rule_data_upgrades_must_be_declared_and_explained() {
    let from = unique_zone().identity();
    let to = zone(unique_zone().transitions(), "2024b").identity();
    let upgrade = RuleDataUpgrade::new(from.clone(), to.clone(), "shift-rule-v1", true)
        .unwrap_or_else(|error| panic!("the declared upgrade is valid: {error}"));
    assert_eq!(upgrade.from(), &from);
    assert_eq!(upgrade.to(), &to);
    assert_eq!(upgrade.migration(), "shift-rule-v1");
    for (candidate_from, candidate_to, migration, declared) in [
        (from.clone(), to.clone(), "", true),
        (from.clone(), to.clone(), "   ", true),
        (from.clone(), to.clone(), "shift-rule-v1", false),
        (from.clone(), from.clone(), "shift-rule-v1", true),
    ] {
        let error = refuse(
            RuleDataUpgrade::new(candidate_from, candidate_to, migration, declared),
            "an undeclared, unexplained, or no-op upgrade",
        );
        assert_eq!(error.code(), LocaleDiagnosticCode::SilentRuleDataUpgrade);
        assert_eq!(error.requirement(), LOCALE_CLAUSES[10]);
    }
}

#[test]
fn stale_rule_data_is_refused_and_durable_replay_retains_its_identity() {
    let rules = unique_zone();
    let identity = rules.identity();
    let observation = Instant::from_seconds(BASE_LOCAL)
        .unwrap_or_else(|error| panic!("the fixture instant is valid: {error}"));
    let record = DurableTemporalRecord::new(
        identity.clone(),
        observation.clone(),
        Some(locale()),
        Disambiguation::Reject,
    );
    assert_eq!(record.rule_data(), &identity);
    assert_eq!(record.observation(), &observation);
    assert_eq!(record.locale(), Some(&locale()));
    let mut available = BTreeSet::new();
    available.insert(identity.clone());
    assert_eq!(record.replay(&available), Ok(observation.clone()));
    let error = refuse(
        record.replay(&BTreeSet::new()),
        "replay of unavailable rule data",
    );
    assert_eq!(error.code(), LocaleDiagnosticCode::RuleDataUnavailable);
    assert_eq!(error.requirement(), LOCALE_CLAUSES[11]);
    assert!(require_rule_data_available(&identity, &available).is_ok());
    let superseded = zone(rules.transitions(), "2024b").identity();
    let mut retired = BTreeSet::new();
    retired.insert(superseded.clone());
    assert_eq!(
        refuse(
            require_superseded_refused(&superseded, &retired),
            "a superseded identity"
        )
        .code(),
        LocaleDiagnosticCode::StaleRuleData
    );
    assert_eq!(
        refuse(
            require_superseded_refused(&superseded, &retired),
            "a superseded identity"
        )
        .requirement(),
        LOCALE_CLAUSES[10]
    );
    assert!(require_superseded_refused(&identity, &retired).is_ok());
    assert_eq!(record.disambiguation(), Disambiguation::Reject);
}

#[test]
fn non_claims_are_not_presented_as_guarantees() {
    assert_eq!(LOCALE_NON_CLAIM_ORDER, LocaleNonClaim::ALL);
    assert_eq!(LOCALE_NON_CLAIMS.len(), 12);
    for claim in LocaleNonClaim::ALL {
        assert_eq!(
            LocaleNonClaim::from_wire_name(claim.wire_name()),
            Some(claim)
        );
        assert!(check_locale_non_claims(&[LocaleNonClaimAssertion::new(claim, false)]).is_ok());
        assert_eq!(
            refuse(
                check_locale_non_claims(&[LocaleNonClaimAssertion::new(claim, true)]),
                "a non-claim presented as a guarantee"
            )
            .code(),
            LocaleDiagnosticCode::NonClaimAsGuarantee
        );
    }
    assert!(LOCALE_NON_CLAIMS.iter().all(|claim| !claim.is_empty()));
    assert!(
        LOCALE_NON_CLAIMS
            .iter()
            .any(|claim| claim.contains("host database")),
        "host database quality is a declared non-claim"
    );
}
