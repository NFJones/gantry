//! Canonical RFC 3339 UTC timestamps for portable Gantry events.

use std::fmt;

const SECONDS_PER_DAY: i64 = 86_400;
const MINIMUM_UNIX_SECONDS: i64 = -62_167_219_200;
const MAXIMUM_UNIX_SECONDS: i64 = 253_402_300_799;

/// One checked UTC timestamp with canonical microsecond precision.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcTimestamp(String);

impl UtcTimestamp {
    /// Constructs a timestamp from Unix seconds and a microsecond fraction.
    ///
    /// The supported portable range is `0000-01-01T00:00:00.000000Z` through
    /// `9999-12-31T23:59:59.999999Z`.
    pub fn from_unix_seconds(seconds: i64, microseconds: u32) -> Result<Self, TimestampError> {
        if microseconds > 999_999 {
            return Err(TimestampError::InvalidMicrosecond);
        }
        if !(MINIMUM_UNIX_SECONDS..=MAXIMUM_UNIX_SECONDS).contains(&seconds) {
            return Err(TimestampError::OutOfRange);
        }

        let days = seconds.div_euclid(SECONDS_PER_DAY);
        let seconds_in_day = seconds.rem_euclid(SECONDS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let hour = seconds_in_day / 3_600;
        let minute = (seconds_in_day % 3_600) / 60;
        let second = seconds_in_day % 60;
        Ok(Self(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{microseconds:06}Z"
        )))
    }

    /// Returns the exact canonical RFC 3339 UTC spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Failure to construct a portable UTC timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampError {
    /// The microsecond fraction exceeds `999999`.
    InvalidMicrosecond,
    /// The instant is outside the four-digit RFC 3339 year range.
    OutOfRange,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMicrosecond => "timestamp microsecond fraction is out of range",
            Self::OutOfRange => "timestamp is outside the portable UTC range",
        })
    }
}

impl std::error::Error for TimestampError {}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let shifted = days_since_epoch + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::{TimestampError, UtcTimestamp};

    #[test]
    fn formats_epoch_leap_and_negative_boundaries() {
        assert_eq!(
            UtcTimestamp::from_unix_seconds(0, 0).map(|value| value.to_string()),
            Ok("1970-01-01T00:00:00.000000Z".to_owned())
        );
        assert_eq!(
            UtcTimestamp::from_unix_seconds(951_827_696, 123_456).map(|value| value.to_string()),
            Ok("2000-02-29T12:34:56.123456Z".to_owned())
        );
        assert_eq!(
            UtcTimestamp::from_unix_seconds(-1, 999_999).map(|value| value.to_string()),
            Ok("1969-12-31T23:59:59.999999Z".to_owned())
        );
    }

    #[test]
    fn enforces_four_digit_year_and_microsecond_bounds() {
        assert_eq!(
            UtcTimestamp::from_unix_seconds(-62_167_219_200, 0).map(|value| value.to_string()),
            Ok("0000-01-01T00:00:00.000000Z".to_owned())
        );
        assert_eq!(
            UtcTimestamp::from_unix_seconds(253_402_300_799, 999_999)
                .map(|value| value.to_string()),
            Ok("9999-12-31T23:59:59.999999Z".to_owned())
        );
        assert_eq!(
            UtcTimestamp::from_unix_seconds(0, 1_000_000),
            Err(TimestampError::InvalidMicrosecond)
        );
        assert_eq!(
            UtcTimestamp::from_unix_seconds(253_402_300_800, 0),
            Err(TimestampError::OutOfRange)
        );
    }
}
