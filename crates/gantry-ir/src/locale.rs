//! Pure locale, calendar, civil-time, and rule-data model for `SPEC.md` Section 33.
//!
//! The model records declared machine formats, locale and collation values, calendar
//! and zone rule data with pinned identities, civil-time values with typed gap and
//! repetition outcomes, preference snapshots, target availability, and durable replay
//! facts. It is deliberately not a host clock, a formatter, a database updater, a
//! runtime store, or a durable mechanism: every decision below is a deterministic
//! function of explicit inputs, and no value consults an ambient locale, a host time
//! zone, or an installed database.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use gantry_core::timestamp::UtcTimestamp;

use crate::TargetKind;
use crate::authority::digest_fields;
use crate::manifest::encode_hex;

/// The Section 33 clauses implemented by this pure model, in declaration order.
pub const LOCALE_CLAUSES: [&str; 13] = [
    "GNT-33.0-locale-calendar-civil-time-and-rule-data",
    "GNT-33.1-locale-neutral-machine-formats",
    "GNT-33.2-explicit-locale-and-collation-values",
    "GNT-33.3-civil-time-timestamp-and-offset-values",
    "GNT-33.4-typed-gap-and-repetition",
    "GNT-33.5-pinned-rule-data-identity",
    "GNT-33.6-preference-snapshots",
    "GNT-33.7-target-availability",
    "GNT-33.8-presentation-separation",
    "GNT-33.9-monotonic-and-wall-separation",
    "GNT-33.10-rule-data-upgrade-and-staleness",
    "GNT-33.11-durable-replay-retention",
    "GNT-33.12-locale-and-time-non-claims",
];

/// The maximum admitted locale identifier length in bytes.
pub const MAX_LOCALE_IDENTIFIER_BYTES: usize = 64;

/// The maximum admitted rule-data identifier or version length in bytes.
pub const MAX_RULE_DATA_IDENTIFIER_BYTES: usize = 128;

/// The maximum admitted absolute offset in seconds (eighteen hours).
pub const MAX_OFFSET_SECONDS: i32 = 64_800;

/// The maximum admitted number of declared zone transitions.
pub const MAX_RULE_DATA_TRANSITIONS: usize = 4_096;

/// The maximum admitted presentation text length in bytes.
pub const MAX_PRESENTATION_TEXT_BYTES: usize = 4_096;

/// One closed machine format of `GNT-33.1-locale-neutral-machine-formats`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MachineFormat {
    /// A civil date and time.
    CivilDateTime,
    /// An exact signed duration.
    Duration,
    /// One canonical UTC instant.
    Instant,
    /// An exact signed offset.
    Offset,
}

impl MachineFormat {
    /// Every format in exact wire-name order.
    pub const ALL: [Self; 4] = [
        Self::CivilDateTime,
        Self::Duration,
        Self::Instant,
        Self::Offset,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::CivilDateTime => "civil-date-time",
            Self::Duration => "duration",
            Self::Instant => "instant",
            Self::Offset => "offset",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|format| format.wire_name() == value)
    }
}

/// One closed collation identity of `GNT-33.2-explicit-locale-and-collation-values`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CollationIdentity {
    /// Byte-order collation, which is the locale-neutral default.
    Binary,
    /// The pinned Unicode collation of the declared data version.
    UnicodeDefault,
}

impl CollationIdentity {
    /// Every identity in exact wire-name order.
    pub const ALL: [Self; 2] = [Self::Binary, Self::UnicodeDefault];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::UnicodeDefault => "unicode-default",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|identity| identity.wire_name() == value)
    }
}

/// One closed calendar identity of `GNT-33.3-civil-time-timestamp-and-offset-values`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CalendarIdentity {
    /// The proleptic Gregorian calendar.
    ProlepticGregorian,
}

impl CalendarIdentity {
    /// Every identity in exact wire-name order.
    pub const ALL: [Self; 1] = [Self::ProlepticGregorian];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ProlepticGregorian => "proleptic-gregorian",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|identity| identity.wire_name() == value)
    }
}

/// One closed rule-data kind of `GNT-33.5-pinned-rule-data-identity`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RuleDataKind {
    /// Calendar rule data.
    Calendar,
    /// Locale and collation rule data.
    Locale,
    /// Time-zone transition rule data.
    Zone,
}

impl RuleDataKind {
    /// Every kind in exact wire-name order.
    pub const ALL: [Self; 3] = [Self::Calendar, Self::Locale, Self::Zone];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Calendar => "calendar",
            Self::Locale => "locale",
            Self::Zone => "zone",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.wire_name() == value)
    }
}

/// One typed refusal from the pure locale model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocaleError {
    code: LocaleDiagnosticCode,
    detail: String,
}

impl LocaleError {
    /// Builds one refusal with its frozen diagnostic and a bounded detail message.
    #[must_use]
    pub fn new(code: LocaleDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the frozen diagnostic code.
    #[must_use]
    pub const fn code(&self) -> LocaleDiagnosticCode {
        self.code
    }

    /// Returns the owning clause of the frozen diagnostic code.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        self.code.requirement()
    }

    /// Returns the bounded detail message.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for LocaleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for LocaleError {}

/// One frozen locale diagnostic of `GNT-33.12`-adjacent clause registry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LocaleDiagnosticCode {
    /// `locale-ambient-preference`
    AmbientPreference,
    /// `locale-ambiguous-civil-time`
    AmbiguousCivilTime,
    /// `locale-host-consultation-refused`
    HostConsultationRefused,
    /// `locale-invalid-civil-value`
    InvalidCivilValue,
    /// `locale-invalid-locale-identity`
    InvalidLocaleIdentity,
    /// `locale-invalid-machine-format`
    InvalidMachineFormat,
    /// `locale-missing-disambiguation`
    MissingDisambiguation,
    /// `locale-nonexistent-civil-time`
    NonexistentCivilTime,
    /// `locale-non-claim-as-guarantee`
    NonClaimAsGuarantee,
    /// `locale-rule-data-identity-mismatch`
    RuleDataIdentityMismatch,
    /// `locale-silent-rule-data-upgrade`
    SilentRuleDataUpgrade,
    /// `locale-stale-rule-data`
    StaleRuleData,
    /// `locale-unsupported-locale-data`
    UnsupportedLocaleData,
}

impl LocaleDiagnosticCode {
    /// Every diagnostic in canonical spelling order.
    pub const ALL: [Self; 13] = [
        Self::AmbientPreference,
        Self::AmbiguousCivilTime,
        Self::HostConsultationRefused,
        Self::InvalidCivilValue,
        Self::InvalidLocaleIdentity,
        Self::InvalidMachineFormat,
        Self::MissingDisambiguation,
        Self::NonClaimAsGuarantee,
        Self::NonexistentCivilTime,
        Self::RuleDataIdentityMismatch,
        Self::SilentRuleDataUpgrade,
        Self::StaleRuleData,
        Self::UnsupportedLocaleData,
    ];

    /// Returns the frozen diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AmbientPreference => "locale-ambient-preference",
            Self::AmbiguousCivilTime => "locale-ambiguous-civil-time",
            Self::HostConsultationRefused => "locale-host-consultation-refused",
            Self::InvalidCivilValue => "locale-invalid-civil-value",
            Self::InvalidLocaleIdentity => "locale-invalid-locale-identity",
            Self::InvalidMachineFormat => "locale-invalid-machine-format",
            Self::MissingDisambiguation => "locale-missing-disambiguation",
            Self::NonexistentCivilTime => "locale-nonexistent-civil-time",
            Self::NonClaimAsGuarantee => "locale-non-claim-as-guarantee",
            Self::RuleDataIdentityMismatch => "locale-rule-data-identity-mismatch",
            Self::SilentRuleDataUpgrade => "locale-silent-rule-data-upgrade",
            Self::StaleRuleData => "locale-stale-rule-data",
            Self::UnsupportedLocaleData => "locale-unsupported-locale-data",
        }
    }

    /// Strictly decodes one frozen diagnostic spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == value)
    }

    /// Returns the sole owning requirement clause.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::InvalidMachineFormat => LOCALE_CLAUSES[1],
            Self::InvalidLocaleIdentity => LOCALE_CLAUSES[2],
            Self::InvalidCivilValue => LOCALE_CLAUSES[3],
            Self::AmbiguousCivilTime | Self::NonexistentCivilTime | Self::MissingDisambiguation => {
                LOCALE_CLAUSES[4]
            }
            Self::RuleDataIdentityMismatch => LOCALE_CLAUSES[5],
            Self::AmbientPreference => LOCALE_CLAUSES[6],
            Self::UnsupportedLocaleData => LOCALE_CLAUSES[7],
            Self::HostConsultationRefused => LOCALE_CLAUSES[9],
            Self::SilentRuleDataUpgrade | Self::StaleRuleData => LOCALE_CLAUSES[10],
            Self::NonClaimAsGuarantee => LOCALE_CLAUSES[12],
        }
    }
}

impl fmt::Display for LocaleDiagnosticCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One checked instant in the landed canonical form with its exact Unix seconds.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Instant {
    seconds: i64,
    canonical: UtcTimestamp,
}

impl Instant {
    /// Builds one instant from exact Unix seconds.
    pub fn from_seconds(seconds: i64) -> Result<Self, LocaleError> {
        let canonical = UtcTimestamp::from_unix_seconds(seconds, 0).map_err(|error| {
            LocaleError::new(
                LocaleDiagnosticCode::InvalidCivilValue,
                format!("{seconds} is outside the supported instant range: {error}"),
            )
        })?;
        Ok(Self { seconds, canonical })
    }

    /// Parses one exact canonical machine-format instant.
    pub fn parse(value: &str) -> Result<Self, LocaleError> {
        let canonical = UtcTimestamp::parse(value).map_err(|error| {
            LocaleError::new(
                LocaleDiagnosticCode::InvalidMachineFormat,
                format!("`{value}` is not a canonical instant: {error}"),
            )
        })?;
        let seconds = unix_seconds_of(&canonical).ok_or_else(|| {
            LocaleError::new(
                LocaleDiagnosticCode::InvalidMachineFormat,
                format!("`{value}` does not name a supported instant"),
            )
        })?;
        Ok(Self { seconds, canonical })
    }

    /// Returns the exact Unix seconds.
    #[must_use]
    pub const fn seconds(&self) -> i64 {
        self.seconds
    }

    /// Returns the landed canonical timestamp.
    #[must_use]
    pub const fn canonical(&self) -> &UtcTimestamp {
        &self.canonical
    }

    /// Returns the exact canonical text.
    #[must_use]
    pub fn to_canonical_string(&self) -> String {
        self.canonical.to_string()
    }
}

/// Parses the exact Unix seconds of one landed canonical timestamp.
fn unix_seconds_of(value: &UtcTimestamp) -> Option<i64> {
    let text = value.to_string();
    let (date, clock) = text.split_once('T')?;
    let mut date_fields = date.split('-');
    let year = date_fields.next()?.parse::<i64>().ok()?;
    let month = date_fields.next()?.parse::<i64>().ok()?;
    let day = date_fields.next()?.parse::<i64>().ok()?;
    let mut clock_fields = clock.trim_end_matches('Z').split(':');
    let hour = clock_fields.next()?.parse::<i64>().ok()?;
    let minute = clock_fields.next()?.parse::<i64>().ok()?;
    let second = clock_fields
        .next()?
        .split('.')
        .next()?
        .parse::<i64>()
        .ok()?;
    let days = civil_to_days(year, month, day);
    days.checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)
}

/// Returns the days since the Unix epoch for one proleptic Gregorian date.
fn civil_to_days(year: i64, month: i64, day: i64) -> i64 {
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = if shifted_year >= 0 {
        shifted_year
    } else {
        shifted_year - 399
    } / 400;
    let year_of_era = shifted_year - era * 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// One declared exact duration of `GNT-33.1-locale-neutral-machine-formats`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Duration {
    seconds: i64,
}

impl Duration {
    /// Declares one exact signed duration in seconds.
    pub fn new(seconds: i64) -> Result<Self, LocaleError> {
        Ok(Self { seconds })
    }

    /// Returns the exact signed seconds.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }
}

/// One declared exact offset of `GNT-33.3-civil-time-timestamp-and-offset-values`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Offset {
    seconds: i32,
}

impl Offset {
    /// Declares one exact offset in seconds; the declared bound is eighteen hours.
    pub fn new(seconds: i32) -> Result<Self, LocaleError> {
        if seconds.unsigned_abs() > MAX_OFFSET_SECONDS.unsigned_abs() {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidCivilValue,
                format!("offset {seconds} exceeds the declared bound"),
            ));
        }
        Ok(Self { seconds })
    }

    /// Returns the exact signed seconds.
    #[must_use]
    pub const fn seconds(self) -> i32 {
        self.seconds
    }
}

/// One declared locale and collation value of `GNT-33.2-explicit-locale-and-collation-values`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LocaleValue {
    identifier: String,
    data_version: String,
    collation: CollationIdentity,
}

impl LocaleValue {
    /// Declares one explicit locale value; malformed, oversized, or empty parts are refused.
    pub fn new(
        identifier: &str,
        data_version: &str,
        collation: CollationIdentity,
    ) -> Result<Self, LocaleError> {
        if identifier.trim().is_empty() || identifier.len() > MAX_LOCALE_IDENTIFIER_BYTES {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidLocaleIdentity,
                "a locale identifier must be nonempty and bounded",
            ));
        }
        if identifier.chars().any(|scalar| scalar.is_whitespace()) {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidLocaleIdentity,
                format!("locale identifier `{identifier}` carries interior whitespace"),
            ));
        }
        if data_version.trim().is_empty() || data_version.len() > MAX_RULE_DATA_IDENTIFIER_BYTES {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidLocaleIdentity,
                "a locale data version must be nonempty and bounded",
            ));
        }
        Ok(Self {
            identifier: identifier.to_owned(),
            data_version: data_version.to_owned(),
            collation,
        })
    }

    /// Returns the declared locale identifier.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Returns the declared data version.
    #[must_use]
    pub fn data_version(&self) -> &str {
        &self.data_version
    }

    /// Returns the declared collation identity.
    #[must_use]
    pub const fn collation(&self) -> CollationIdentity {
        self.collation
    }
}

/// One declared civil-time value of `GNT-33.3-civil-time-timestamp-and-offset-values`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CivilValue {
    calendar: CalendarIdentity,
    year: i64,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl CivilValue {
    /// Declares one civil value; every field is bounds-checked rather than normalized.
    pub fn new(
        calendar: CalendarIdentity,
        year: i64,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, LocaleError> {
        if hour > 23 || minute > 59 || second > 59 {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidCivilValue,
                "a civil time field is outside its bound",
            ));
        }
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidCivilValue,
                "a civil date field is outside its bound",
            ));
        }
        Ok(Self {
            calendar,
            year,
            month,
            day,
            hour,
            minute,
            second,
        })
    }

    /// Returns the declared calendar identity.
    #[must_use]
    pub const fn calendar(self) -> CalendarIdentity {
        self.calendar
    }

    /// Returns the civil date and time fields.
    #[must_use]
    pub const fn fields(self) -> (i64, u8, u8, u8, u8, u8) {
        (
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )
    }

    /// Returns the local seconds since the Unix epoch, before any offset.
    #[must_use]
    pub fn local_seconds(self) -> i64 {
        let days = civil_to_days(self.year, i64::from(self.month), i64::from(self.day));
        days * 86_400
            + i64::from(self.hour) * 3_600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }
}

/// Returns the number of days of one proleptic Gregorian month.
fn days_in_month(year: i64, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Returns whether one proleptic Gregorian year is a leap year.
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// One declared zone transition of `GNT-33.5-pinned-rule-data-identity`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ZoneTransition {
    at_seconds: i64,
    at: UtcTimestamp,
    offset: Offset,
}

impl ZoneTransition {
    /// Declares one transition instant and the offset it installs.
    pub fn new(at_seconds: i64, offset: Offset) -> Result<Self, LocaleError> {
        let at = UtcTimestamp::from_unix_seconds(at_seconds, 0).map_err(|error| {
            LocaleError::new(
                LocaleDiagnosticCode::InvalidCivilValue,
                format!("transition instant {at_seconds} is unsupported: {error}"),
            )
        })?;
        Ok(Self {
            at_seconds,
            at,
            offset,
        })
    }

    /// Returns the exact transition instant in Unix seconds.
    #[must_use]
    pub const fn at_seconds(&self) -> i64 {
        self.at_seconds
    }

    /// Returns the landed canonical transition instant.
    #[must_use]
    pub const fn at(&self) -> &UtcTimestamp {
        &self.at
    }

    /// Returns the installed offset.
    #[must_use]
    pub const fn offset(&self) -> Offset {
        self.offset
    }
}

/// One typed rule-data identity of `GNT-33.5-pinned-rule-data-identity`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuleDataIdentity(Arc<str>);

impl RuleDataIdentity {
    /// Encodes one accepted digest.
    #[must_use]
    fn from_digest(digest: [u8; 32]) -> Self {
        Self(Arc::from(encode_hex(&digest)))
    }

    /// Returns the exact lowercase hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One declared rule data set of `GNT-33.5-pinned-rule-data-identity`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleData {
    kind: RuleDataKind,
    identifier: String,
    version: String,
    transitions: Vec<ZoneTransition>,
    facts: BTreeSet<String>,
}

impl RuleData {
    /// Declares one rule data set; malformed identities, unordered transitions,
    /// oversized transition counts, and kind-inapplicable contents are refused.
    pub fn new(
        kind: RuleDataKind,
        identifier: &str,
        version: &str,
        transitions: &[ZoneTransition],
        facts: &[&str],
    ) -> Result<Self, LocaleError> {
        if identifier.trim().is_empty() || identifier.len() > MAX_RULE_DATA_IDENTIFIER_BYTES {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidLocaleIdentity,
                "a rule-data identifier must be nonempty and bounded",
            ));
        }
        if version.trim().is_empty() || version.len() > MAX_RULE_DATA_IDENTIFIER_BYTES {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidLocaleIdentity,
                "a rule-data version must be nonempty and bounded",
            ));
        }
        if transitions.len() > MAX_RULE_DATA_TRANSITIONS {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidCivilValue,
                "a rule data set exceeds the declared transition bound",
            ));
        }
        if !transitions
            .windows(2)
            .all(|pair| pair[0].at_seconds() < pair[1].at_seconds())
        {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidCivilValue,
                "zone transitions must be strictly increasing",
            ));
        }
        if kind == RuleDataKind::Zone && transitions.is_empty() {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidCivilValue,
                "zone rule data declares no transition",
            ));
        }
        if kind != RuleDataKind::Zone && !transitions.is_empty() {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidCivilValue,
                "only zone rule data declares transitions",
            ));
        }
        let mut declared = BTreeSet::new();
        for fact in facts {
            if fact.trim().is_empty() || fact.len() > MAX_RULE_DATA_IDENTIFIER_BYTES {
                return Err(LocaleError::new(
                    LocaleDiagnosticCode::InvalidLocaleIdentity,
                    "a rule-data fact must be nonempty and bounded",
                ));
            }
            declared.insert((*fact).to_owned());
        }
        Ok(Self {
            kind,
            identifier: identifier.to_owned(),
            version: version.to_owned(),
            transitions: transitions.to_vec(),
            facts: declared,
        })
    }

    /// Returns the declared kind.
    #[must_use]
    pub const fn kind(&self) -> RuleDataKind {
        self.kind
    }

    /// Returns the declared identifier.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Returns the declared version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the declared transitions.
    #[must_use]
    pub fn transitions(&self) -> &[ZoneTransition] {
        &self.transitions
    }

    /// Returns the declared data facts.
    #[must_use]
    pub fn facts(&self) -> &BTreeSet<String> {
        &self.facts
    }

    /// Returns the identity over every declared fact.
    #[must_use]
    pub fn identity(&self) -> RuleDataIdentity {
        let mut fields: Vec<Vec<u8>> = vec![
            self.kind.wire_name().as_bytes().to_vec(),
            self.identifier.as_bytes().to_vec(),
            self.version.as_bytes().to_vec(),
        ];
        for transition in &self.transitions {
            fields.push(transition.at_seconds().to_be_bytes().to_vec());
            fields.push(transition.offset().seconds().to_be_bytes().to_vec());
        }
        for fact in &self.facts {
            fields.push(fact.as_bytes().to_vec());
        }
        let borrowed = fields.iter().map(Vec::as_slice).collect::<Vec<&[u8]>>();
        RuleDataIdentity::from_digest(digest_fields("gantry.locale.rule-data.v1", &borrowed))
    }

    /// Returns the offset in force at one instant.
    #[must_use]
    pub fn offset_at(&self, seconds: i64) -> Option<Offset> {
        let first = self.transitions.first()?;
        let mut in_force = first.offset();
        for transition in self.transitions.iter().skip(1) {
            if seconds >= transition.at_seconds() {
                in_force = transition.offset();
            }
        }
        Some(in_force)
    }
}

/// One typed civil-time classification of `GNT-33.4-typed-gap-and-repetition`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CivilResolution {
    /// The civil time lies in a gap and names no instant.
    Gap {
        /// The exact gap length in seconds.
        gap_seconds: i64,
    },
    /// The civil time is repeated and names two instants.
    Repetition {
        /// The earlier instant of the repetition.
        first: Instant,
        /// The later instant of the repetition.
        second: Instant,
    },
    /// The civil time names exactly one instant.
    Unique {
        /// The named instant.
        instant: Instant,
    },
}

impl CivilResolution {
    /// Returns the exact portable classification spelling.
    #[must_use]
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::Gap { .. } => "gap",
            Self::Repetition { .. } => "repetition",
            Self::Unique { .. } => "unique",
        }
    }
}

/// One explicit disambiguation of `GNT-33.4-typed-gap-and-repetition`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Disambiguation {
    /// Choose the earlier instant, or the pre-transition offset across a gap.
    PreferEarlier,
    /// Choose the later instant, or the post-transition offset across a gap.
    PreferLater,
    /// Refuse any civil time that is not unique.
    Reject,
}

impl Disambiguation {
    /// Every declaration in exact wire-name order.
    pub const ALL: [Self; 3] = [Self::PreferEarlier, Self::PreferLater, Self::Reject];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::PreferEarlier => "prefer-earlier",
            Self::PreferLater => "prefer-later",
            Self::Reject => "reject",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|declaration| declaration.wire_name() == value)
    }
}

/// Classifies one civil time against one pinned zone rule data set.
pub fn classify_civil(civil: CivilValue, rules: &RuleData) -> Result<CivilResolution, LocaleError> {
    if rules.kind() != RuleDataKind::Zone {
        return Err(LocaleError::new(
            LocaleDiagnosticCode::InvalidCivilValue,
            "civil classification requires zone rule data",
        ));
    }
    let local = civil.local_seconds();
    let mut candidates: Vec<Instant> = Vec::new();
    let offsets = rules
        .transitions()
        .iter()
        .map(|transition| transition.offset().seconds())
        .collect::<BTreeSet<i32>>();
    for offset in offsets {
        let Some(candidate_seconds) = local.checked_sub(i64::from(offset)) else {
            continue;
        };
        if rules.offset_at(candidate_seconds).map(Offset::seconds) != Some(offset) {
            continue;
        }
        let instant = Instant::from_seconds(candidate_seconds)?;
        if !candidates.contains(&instant) {
            candidates.push(instant);
        }
    }
    candidates.sort();
    match candidates.len() {
        0 => {
            let gap_seconds = rules
                .transitions()
                .windows(2)
                .find_map(|pair| {
                    let before = pair[0].offset().seconds();
                    let after = pair[1].offset().seconds();
                    if after <= before {
                        return None;
                    }
                    let gap_start = pair[1].at_seconds() + i64::from(before);
                    let gap_end = pair[1].at_seconds() + i64::from(after);
                    (gap_start <= local && local < gap_end).then_some(i64::from(after - before))
                })
                .unwrap_or_default();
            Ok(CivilResolution::Gap { gap_seconds })
        }
        1 => Ok(CivilResolution::Unique {
            instant: candidates[0].clone(),
        }),
        _ => Ok(CivilResolution::Repetition {
            first: candidates[0].clone(),
            second: candidates[1].clone(),
        }),
    }
}

/// Resolves one civil time under one explicit disambiguation.
///
/// A non-unique civil time without a declared disambiguation is refused, and a
/// declaration that refuses the classification is refused rather than overridden.
pub fn resolve_civil(
    civil: CivilValue,
    rules: &RuleData,
    disambiguation: Option<Disambiguation>,
) -> Result<Instant, LocaleError> {
    match classify_civil(civil, rules)? {
        CivilResolution::Unique { instant } => Ok(instant),
        CivilResolution::Gap { gap_seconds } => match disambiguation {
            None => Err(LocaleError::new(
                LocaleDiagnosticCode::MissingDisambiguation,
                "a nonexistent civil time requires an explicit disambiguation",
            )),
            Some(Disambiguation::Reject) => Err(LocaleError::new(
                LocaleDiagnosticCode::NonexistentCivilTime,
                format!("the civil time is nonexistent across a {gap_seconds}-second gap"),
            )),
            Some(declaration) => {
                let local = civil.local_seconds();
                let candidates = rules
                    .transitions()
                    .windows(2)
                    .find_map(|pair| {
                        let before = pair[0].offset().seconds();
                        let after = pair[1].offset().seconds();
                        if after <= before {
                            return None;
                        }
                        let gap_start = pair[1].at_seconds() + i64::from(before);
                        let gap_end = pair[1].at_seconds() + i64::from(after);
                        (gap_start <= local && local < gap_end).then_some((before, after))
                    })
                    .ok_or_else(|| {
                        LocaleError::new(
                            LocaleDiagnosticCode::NonexistentCivilTime,
                            "the civil time is nonexistent but its gap is not declared",
                        )
                    })?;
                let offset = match declaration {
                    Disambiguation::PreferEarlier => candidates.0,
                    Disambiguation::PreferLater => candidates.1,
                    Disambiguation::Reject => unreachable!("rejection is handled above"),
                };
                Instant::from_seconds(local - i64::from(offset))
            }
        },
        CivilResolution::Repetition { first, second } => match disambiguation {
            None => Err(LocaleError::new(
                LocaleDiagnosticCode::MissingDisambiguation,
                "a repeated civil time requires an explicit disambiguation",
            )),
            Some(Disambiguation::Reject) => Err(LocaleError::new(
                LocaleDiagnosticCode::AmbiguousCivilTime,
                format!(
                    "the civil time is repeated between {} and {}",
                    first.to_canonical_string(),
                    second.to_canonical_string()
                ),
            )),
            Some(Disambiguation::PreferEarlier) => Ok(first),
            Some(Disambiguation::PreferLater) => Ok(second),
        },
    }
}

/// One pinned rule-data binding of `GNT-33.5-pinned-rule-data-identity`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleDataBinding {
    pinned: RuleDataIdentity,
    presented: RuleDataIdentity,
}

impl RuleDataBinding {
    /// Binds one pinned identity to one presented identity.
    #[must_use]
    pub const fn new(pinned: RuleDataIdentity, presented: RuleDataIdentity) -> Self {
        Self { pinned, presented }
    }

    /// Refuses a presented identity that differs from the pinned identity.
    pub fn verify(&self) -> Result<(), LocaleError> {
        if self.pinned != self.presented {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::RuleDataIdentityMismatch,
                format!(
                    "presented rule data `{}` differs from pinned `{}`",
                    self.presented.as_str(),
                    self.pinned.as_str()
                ),
            ));
        }
        Ok(())
    }
}

/// One declared rule-data upgrade of `GNT-33.10-rule-data-upgrade-and-staleness`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleDataUpgrade {
    from: RuleDataIdentity,
    to: RuleDataIdentity,
    migration: String,
}

impl RuleDataUpgrade {
    /// Declares one upgrade; an undeclared, no-op, or unexplained replacement is refused.
    pub fn new(
        from: RuleDataIdentity,
        to: RuleDataIdentity,
        migration: &str,
        declared: bool,
    ) -> Result<Self, LocaleError> {
        if from == to {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::SilentRuleDataUpgrade,
                "an upgrade must change the pinned rule-data identity",
            ));
        }
        if !declared || migration.trim().is_empty() {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::SilentRuleDataUpgrade,
                "an upgrade must declare its source, target, and migration",
            ));
        }
        Ok(Self {
            from,
            to,
            migration: migration.to_owned(),
        })
    }

    /// Returns the superseded identity.
    #[must_use]
    pub const fn from(&self) -> &RuleDataIdentity {
        &self.from
    }

    /// Returns the target identity.
    #[must_use]
    pub const fn to(&self) -> &RuleDataIdentity {
        &self.to
    }

    /// Returns the declared migration.
    #[must_use]
    pub fn migration(&self) -> &str {
        &self.migration
    }
}

/// Refuses one rule-data identity that the declared data set does not carry.
pub fn require_rule_data_available(
    identity: &RuleDataIdentity,
    available: &BTreeSet<RuleDataIdentity>,
) -> Result<(), LocaleError> {
    if !available.contains(identity) {
        return Err(LocaleError::new(
            LocaleDiagnosticCode::StaleRuleData,
            format!("rule data `{}` is unavailable", identity.as_str()),
        ));
    }
    Ok(())
}

/// One closed selection origin of `GNT-33.6-preference-snapshots`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PreferenceOrigin {
    /// An ambient host read, which is refused.
    AmbientHost,
    /// One explicit entry snapshot.
    EntrySnapshot,
    /// One visible operation.
    VisibleOperation,
}

impl PreferenceOrigin {
    /// Every origin in exact wire-name order.
    pub const ALL: [Self; 3] = [
        Self::AmbientHost,
        Self::EntrySnapshot,
        Self::VisibleOperation,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AmbientHost => "ambient-host",
            Self::EntrySnapshot => "entry-snapshot",
            Self::VisibleOperation => "visible-operation",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|origin| origin.wire_name() == value)
    }
}

/// One immutable preference snapshot of `GNT-33.6-preference-snapshots`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreferenceSnapshot {
    locale: Option<LocaleValue>,
    zone: Option<RuleDataIdentity>,
    origin: PreferenceOrigin,
}

impl PreferenceSnapshot {
    /// Takes one snapshot; an ambient host read is refused.
    pub fn new(
        locale: Option<LocaleValue>,
        zone: Option<RuleDataIdentity>,
        origin: PreferenceOrigin,
    ) -> Result<Self, LocaleError> {
        if origin == PreferenceOrigin::AmbientHost {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::AmbientPreference,
                "an ambient host preference is refused; take an explicit snapshot",
            ));
        }
        Ok(Self {
            locale,
            zone,
            origin,
        })
    }

    /// Returns the snapshotted locale value.
    #[must_use]
    pub const fn locale(&self) -> Option<&LocaleValue> {
        self.locale.as_ref()
    }

    /// Returns the snapshotted zone rule-data identity.
    #[must_use]
    pub const fn zone(&self) -> Option<&RuleDataIdentity> {
        self.zone.as_ref()
    }

    /// Returns the selection origin.
    #[must_use]
    pub const fn origin(&self) -> PreferenceOrigin {
        self.origin
    }

    /// Returns whether the snapshot is re-read implicitly; it never is.
    #[must_use]
    pub const fn is_implicitly_reread(&self) -> bool {
        false
    }
}

/// One target data-availability declaration of `GNT-33.7-target-availability`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetDataAvailability {
    target: TargetKind,
    identities: BTreeSet<RuleDataIdentity>,
}

impl TargetDataAvailability {
    /// Declares exactly the data identities one target carries.
    #[must_use]
    pub fn new(target: TargetKind, identities: &[RuleDataIdentity]) -> Self {
        Self {
            target,
            identities: identities.iter().cloned().collect(),
        }
    }

    /// Returns the declared target.
    #[must_use]
    pub const fn target(&self) -> TargetKind {
        self.target
    }

    /// Returns the carried identities.
    #[must_use]
    pub fn identities(&self) -> &BTreeSet<RuleDataIdentity> {
        &self.identities
    }

    /// Requires one data identity on this target; an undeclared identity is unavailable.
    pub fn require(&self, identity: &RuleDataIdentity) -> Result<(), LocaleError> {
        if !self.identities.contains(identity) {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::UnsupportedLocaleData,
                format!(
                    "target `{}` does not carry rule data `{}`",
                    self.target.wire_name(),
                    identity.as_str()
                ),
            ));
        }
        Ok(())
    }
}

/// One presentation-only text of `GNT-33.8-presentation-separation`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentationText {
    locale: LocaleValue,
    text: String,
}

impl PresentationText {
    /// Declares one bounded display text produced under one explicit locale.
    pub fn new(locale: &LocaleValue, text: &str) -> Result<Self, LocaleError> {
        if text.len() > MAX_PRESENTATION_TEXT_BYTES {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::InvalidMachineFormat,
                "presentation text exceeds the declared bound",
            ));
        }
        Ok(Self {
            locale: locale.clone(),
            text: text.to_owned(),
        })
    }

    /// Returns the locale the text was produced under.
    #[must_use]
    pub const fn locale(&self) -> &LocaleValue {
        &self.locale
    }

    /// Returns the display text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Refuses any attempt to treat presentation text as value authority.
    pub fn as_value_authority(&self) -> Result<(), LocaleError> {
        Err(LocaleError::new(
            LocaleDiagnosticCode::InvalidMachineFormat,
            "presentation text is never value authority",
        ))
    }
}

/// One monotonic deadline of `GNT-33.9-monotonic-and-wall-separation`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Deadline {
    ticks: u64,
}

impl Deadline {
    /// Declares one monotonic deadline.
    #[must_use]
    pub const fn from_monotonic(ticks: u64) -> Self {
        Self { ticks }
    }

    /// Refuses a deadline derived from a wall clock or civil value.
    pub fn from_wall(_instant: &Instant) -> Result<Self, LocaleError> {
        Err(LocaleError::new(
            LocaleDiagnosticCode::HostConsultationRefused,
            "a deadline MUST NOT be derived from a wall clock or civil time",
        ))
    }

    /// Returns the declared monotonic ticks.
    #[must_use]
    pub const fn ticks(self) -> u64 {
        self.ticks
    }
}

/// One durable temporal record of `GNT-33.11-durable-replay-retention`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableTemporalRecord {
    rule_data: RuleDataIdentity,
    observation: Instant,
    locale: Option<LocaleValue>,
}

impl DurableTemporalRecord {
    /// Records one committed observation with the rule data and locale it used.
    #[must_use]
    pub fn new(
        rule_data: RuleDataIdentity,
        observation: Instant,
        locale: Option<LocaleValue>,
    ) -> Self {
        Self {
            rule_data,
            observation,
            locale,
        }
    }

    /// Returns the retained rule-data identity.
    #[must_use]
    pub const fn rule_data(&self) -> &RuleDataIdentity {
        &self.rule_data
    }

    /// Returns the retained observation choice.
    #[must_use]
    pub const fn observation(&self) -> &Instant {
        &self.observation
    }

    /// Returns the retained locale value.
    #[must_use]
    pub const fn locale(&self) -> Option<&LocaleValue> {
        self.locale.as_ref()
    }

    /// Replays the committed observation without consulting the host.
    pub fn replay(&self, available: &BTreeSet<RuleDataIdentity>) -> Result<Instant, LocaleError> {
        require_rule_data_available(&self.rule_data, available)?;
        Ok(self.observation.clone())
    }
}

/// The closed locale non-claim vocabulary of `GNT-33.12-locale-and-time-non-claims`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LocaleNonClaim {
    /// Complete locale, calendar, or zone coverage.
    CoverageCompleteness,
    /// Ordering across differing rule data.
    CrossRuleDataOrdering,
    /// Durable runtime storage, checkpointing, or recovery mechanisms.
    DurableMechanism,
    /// Historical completeness for every past instant.
    HistoricalCompleteness,
    /// A host clock, timer, or scheduler.
    HostClock,
    /// Host database correctness, currency, or stability.
    HostDatabaseQuality,
    /// Leap-second accounting.
    LeapSecondAccounting,
    /// Authority granted by a locale or zone value.
    LocaleAuthority,
    /// Locale-aware comparison as program semantics.
    LocaleComparisonAuthority,
    /// Host subsecond monotonic precision.
    MonotonicPrecision,
    /// Platform formatting, parsing, or collation as authority.
    PlatformFormattingAuthority,
    /// Automatic preference refresh.
    PreferenceAutoRefresh,
}

impl LocaleNonClaim {
    /// Every non-claim in exact wire-name order.
    pub const ALL: [Self; 12] = [
        Self::CoverageCompleteness,
        Self::CrossRuleDataOrdering,
        Self::DurableMechanism,
        Self::HistoricalCompleteness,
        Self::HostClock,
        Self::HostDatabaseQuality,
        Self::LeapSecondAccounting,
        Self::LocaleAuthority,
        Self::LocaleComparisonAuthority,
        Self::MonotonicPrecision,
        Self::PlatformFormattingAuthority,
        Self::PreferenceAutoRefresh,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::CoverageCompleteness => "coverage-completeness",
            Self::CrossRuleDataOrdering => "cross-rule-data-ordering",
            Self::DurableMechanism => "durable-mechanism",
            Self::HistoricalCompleteness => "historical-completeness",
            Self::HostClock => "host-clock",
            Self::HostDatabaseQuality => "host-database-quality",
            Self::LeapSecondAccounting => "leap-second-accounting",
            Self::LocaleAuthority => "locale-authority",
            Self::LocaleComparisonAuthority => "locale-comparison-authority",
            Self::MonotonicPrecision => "monotonic-precision",
            Self::PlatformFormattingAuthority => "platform-formatting-authority",
            Self::PreferenceAutoRefresh => "preference-auto-refresh",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|claim| claim.wire_name() == value)
    }
}

/// The declared locale non-claims of `GNT-33.12-locale-and-time-non-claims`.
pub const LOCALE_NON_CLAIMS: [&str; 12] = [
    "No complete locale, calendar, or zone coverage: the section defines declared values and claims no data completeness.",
    "No ordering across differing rule data: comparing values that rest on different pinned identities is not specified here.",
    "No durable mechanism: storage, checkpointing, and recovery implementations remain downstream owners.",
    "No historical completeness: the section claims nothing about any instant outside the declared transitions.",
    "No host clock, timer, or scheduler: observing wall time is an explicit operation owned elsewhere.",
    "No host database quality: correctness, currency, and stability of any installed database are not promised.",
    "No leap-second accounting: the declared instant is the landed canonical timestamp, with no leap-second table.",
    "No authority from a locale or zone value: these values are portable data only.",
    "No locale-aware comparison as program semantics: collation is presentation behavior.",
    "No monotonic precision guarantee: host resolution and skew remain outside this section.",
    "No platform formatting authority: platform parsers, formatters, and collation implementation are not authoritative.",
    "No automatic preference refresh: a snapshot is taken once and never re-read implicitly.",
];

/// The declared order of the locale non-claims (`GNT-33.12`).
pub const LOCALE_NON_CLAIM_ORDER: [LocaleNonClaim; 12] = LocaleNonClaim::ALL;

/// One presented non-claim assertion (`GNT-33.12`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocaleNonClaimAssertion {
    claim: LocaleNonClaim,
    presented_as_guarantee: bool,
}

impl LocaleNonClaimAssertion {
    /// Records whether one non-claim is presented as a guarantee.
    #[must_use]
    pub const fn new(claim: LocaleNonClaim, presented_as_guarantee: bool) -> Self {
        Self {
            claim,
            presented_as_guarantee,
        }
    }

    /// Returns the non-claim this assertion names.
    #[must_use]
    pub const fn claim(self) -> LocaleNonClaim {
        self.claim
    }

    /// Returns whether the non-claim was presented as a guarantee.
    #[must_use]
    pub const fn presented_as_guarantee(self) -> bool {
        self.presented_as_guarantee
    }
}

/// Refuses any locale non-claim presented as a guarantee.
pub fn check_locale_non_claims(assertions: &[LocaleNonClaimAssertion]) -> Result<(), LocaleError> {
    for assertion in assertions {
        if assertion.presented_as_guarantee() {
            return Err(LocaleError::new(
                LocaleDiagnosticCode::NonClaimAsGuarantee,
                format!(
                    "the non-claim `{}` was presented as a guarantee",
                    assertion.claim().wire_name()
                ),
            ));
        }
    }
    Ok(())
}
