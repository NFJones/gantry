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

    /// Parses one exact canonical RFC 3339 UTC timestamp.
    pub fn parse(value: &str) -> Result<Self, TimestampError> {
        let bytes = value.as_bytes();
        if bytes.len() != 27
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
            || bytes[19] != b'.'
            || bytes[26] != b'Z'
        {
            return Err(TimestampError::InvalidFormat);
        }
        let year = decimal(bytes, 0, 4)?;
        let month = decimal(bytes, 5, 7)?;
        let day = decimal(bytes, 8, 10)?;
        let hour = decimal(bytes, 11, 13)?;
        let minute = decimal(bytes, 14, 16)?;
        let second = decimal(bytes, 17, 19)?;
        let microseconds = decimal(bytes, 20, 26)?;
        if !(1..=12).contains(&month)
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(TimestampError::InvalidFormat);
        }
        let days = days_from_civil(year, month, day);
        let seconds = days
            .checked_mul(SECONDS_PER_DAY)
            .and_then(|value| value.checked_add(i64::from(hour) * 3_600))
            .and_then(|value| value.checked_add(i64::from(minute) * 60))
            .and_then(|value| value.checked_add(i64::from(second)))
            .ok_or(TimestampError::OutOfRange)?;
        let timestamp = Self::from_unix_seconds(seconds, microseconds)?;
        if timestamp.as_str() != value {
            return Err(TimestampError::InvalidFormat);
        }
        Ok(timestamp)
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
    /// The input is not the exact canonical RFC 3339 UTC representation.
    InvalidFormat,
    /// The microsecond fraction exceeds `999999`.
    InvalidMicrosecond,
    /// The instant is outside the four-digit RFC 3339 year range.
    OutOfRange,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFormat => "timestamp is not canonical RFC 3339 UTC",
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

fn decimal(bytes: &[u8], start: usize, end: usize) -> Result<u32, TimestampError> {
    bytes[start..end].iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(*byte - b'0'))
            .ok_or(TimestampError::InvalidFormat)
    })
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
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

    #[test]
    fn parses_only_exact_canonical_timestamps() {
        let canonical = "2000-02-29T12:34:56.123456Z";
        assert_eq!(
            UtcTimestamp::parse(canonical).map(|value| value.to_string()),
            Ok(canonical.to_owned())
        );
        assert_eq!(
            UtcTimestamp::parse("2001-02-29T12:34:56.123456Z"),
            Err(TimestampError::InvalidFormat)
        );
        assert_eq!(
            UtcTimestamp::parse("2000-02-29t12:34:56.123456z"),
            Err(TimestampError::InvalidFormat)
        );
    }
}
