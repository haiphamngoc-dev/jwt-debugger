//! Date, time, and timezone utilities for JWT timestamp handling (e.g. `iat`, `exp`, `nbf`).

use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Local, Utc};
use chrono_tz::Tz;

use super::duration::format_duration_concise;

/// Represents the target timezone for displaying timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimezoneOption {
    /// UTC timezone (`+00:00`).
    Utc,
    /// Host machine local timezone.
    Local,
    /// Specific IANA timezone (e.g., `Asia/Ho_Chi_Minh`, `America/New_York`).
    Iana(Tz),
}

impl FromStr for TimezoneOption {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("utc") || trimmed.eq_ignore_ascii_case("z") {
            Ok(Self::Utc)
        } else if trimmed.eq_ignore_ascii_case("local") {
            Ok(Self::Local)
        } else {
            match Tz::from_str(trimmed) {
                Ok(tz) => Ok(Self::Iana(tz)),
                Err(_) => Err(format!(
                    "Invalid timezone '{trimmed}'. Use 'UTC', 'local', or an IANA name (e.g., 'Asia/Ho_Chi_Minh', 'America/New_York')"
                )),
            }
        }
    }
}

/// Formatted timestamp representation containing Unix epoch, localized date string, UTC ISO string, and relative time.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FormattedTimestamp {
    /// Raw Unix timestamp in seconds.
    pub unix: i64,
    /// Formatted date string in the target timezone.
    pub formatted: String,
    /// Formatted date string in UTC (ISO 8601 / RFC 3339 format).
    pub utc: String,
    /// Relative time difference compared to the reference time (e.g. `"15m ago"`, `"in 1h"`).
    pub relative: String,
}

impl FormattedTimestamp {
    /// Constructs a [`FormattedTimestamp`] from a Unix epoch in seconds, target timezone, and reference `now` time.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - Unix timestamp in seconds (e.g. `exp` claim).
    /// * `tz` - Timezone to format the date in.
    /// * `now` - Reference current time for calculating relative duration.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::Utc;
    /// use jwt_debugger::utils::time::{FormattedTimestamp, TimezoneOption};
    ///
    /// let now = Utc::now();
    /// let ts = FormattedTimestamp::from_unix(1700000000, &TimezoneOption::Utc, now);
    /// assert_eq!(ts.unix, 1700000000);
    /// assert_eq!(ts.utc, "2023-11-14T22:13:20Z");
    /// ```
    pub fn from_unix(timestamp: i64, tz: &TimezoneOption, now: DateTime<Utc>) -> Self {
        let dt_utc = match DateTime::from_timestamp(timestamp, 0) {
            Some(dt) => dt,
            None => {
                return Self {
                    unix: timestamp,
                    formatted: format!("Invalid timestamp ({timestamp})"),
                    utc: format!("Invalid timestamp ({timestamp})"),
                    relative: "invalid date".to_string(),
                };
            }
        };

        let utc_str = dt_utc.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let formatted = match tz {
            TimezoneOption::Utc => dt_utc.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            TimezoneOption::Local => {
                let local_dt = dt_utc.with_timezone(&Local);
                local_dt.format("%Y-%m-%d %H:%M:%S %Z").to_string()
            }
            TimezoneOption::Iana(iana_tz) => {
                let tz_dt = dt_utc.with_timezone(iana_tz);
                tz_dt.format("%Y-%m-%d %H:%M:%S %Z").to_string()
            }
        };

        let relative = format_relative_time(dt_utc, now);

        Self {
            unix: timestamp,
            formatted,
            utc: utc_str,
            relative,
        }
    }
}

/// Formats a target datetime relative to `now` (e.g., `"15m ago"`, `"in 45m"`, `"just now"`).
///
/// # Arguments
///
/// * `target` - The target datetime.
/// * `now` - The reference datetime to compare against.
///
/// # Examples
///
/// ```
/// use chrono::{DateTime, Utc};
/// use jwt_debugger::utils::time::format_relative_time;
///
/// let now = DateTime::from_timestamp(1700000000, 0).unwrap();
/// let past = DateTime::from_timestamp(1700000000 - 900, 0).unwrap();
/// assert_eq!(format_relative_time(past, now), "15m ago");
/// ```
pub fn format_relative_time(target: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let diff = target.signed_duration_since(now);
    let num_secs = diff.num_seconds();

    if num_secs.abs() < 5 {
        return "just now".to_string();
    }

    if num_secs < 0 {
        let abs_dur = Duration::from_secs((-num_secs) as u64);
        format!("{} ago", format_duration_concise(abs_dur))
    } else {
        let abs_dur = Duration::from_secs(num_secs as u64);
        format!("in {}", format_duration_concise(abs_dur))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timezone_option_parsing() {
        assert_eq!(
            TimezoneOption::from_str("utc").unwrap(),
            TimezoneOption::Utc
        );
        assert_eq!(
            TimezoneOption::from_str("local").unwrap(),
            TimezoneOption::Local
        );
        assert_eq!(
            TimezoneOption::from_str("Asia/Ho_Chi_Minh").unwrap(),
            TimezoneOption::Iana(Tz::Asia__Ho_Chi_Minh)
        );
        assert!(TimezoneOption::from_str("Invalid/Tz").is_err());
    }

    #[test]
    fn test_relative_time() {
        let now = DateTime::from_timestamp(1700000000, 0).unwrap();
        let past = DateTime::from_timestamp(1700000000 - 900, 0).unwrap(); // 15 mins ago
        let future = DateTime::from_timestamp(1700000000 + 2700, 0).unwrap(); // 45 mins in future

        assert_eq!(format_relative_time(past, now), "15m ago");
        assert_eq!(format_relative_time(future, now), "in 45m");
    }

    #[test]
    fn test_formatted_timestamp() {
        let now = DateTime::from_timestamp(1700000000, 0).unwrap();
        let ts = FormattedTimestamp::from_unix(1700000000, &TimezoneOption::Utc, now);
        assert_eq!(ts.unix, 1700000000);
        assert_eq!(ts.utc, "2023-11-14T22:13:20Z");
        assert_eq!(ts.formatted, "2023-11-14 22:13:20 UTC");
        assert_eq!(ts.relative, "just now");
    }
}
