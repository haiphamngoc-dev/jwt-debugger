//! Utilities for parsing and formatting human-readable durations.

use std::time::Duration;

/// Parses human-readable duration strings into standard [`Duration`].
///
/// Supports standard units such as seconds (`"30s"`), minutes (`"2m"`),
/// hours (`"1h"`), days (`"1d"`), milliseconds (`"500ms"`), as well as
/// pure numeric values as seconds (e.g. `"60"` -> 60 seconds).
///
/// # Arguments
///
/// * `s` - The duration string slice to parse.
///
/// # Errors
///
/// Returns an error message [`String`] if the string is empty or cannot be parsed.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use jwt_debugger::utils::duration::parse_duration;
///
/// assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
/// assert_eq!(parse_duration("1h 30m").unwrap(), Duration::from_secs(5400));
/// assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
/// ```
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Duration string cannot be empty".to_string());
    }

    // Try standard humantime parser first
    if let Ok(d) = humantime::parse_duration(s) {
        return Ok(d);
    }

    // Fallback if integer seconds is passed without unit
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }

    Err(format!(
        "Invalid duration '{s}'. Examples of valid formats: '30s', '5m', '1h', '2d'"
    ))
}

/// Formats a [`Duration`] into a concise, compact human-readable string.
///
/// Converts total seconds into broken-down days (`d`), hours (`h`), minutes (`m`),
/// and seconds (`s`). If duration is 0, returns `"0s"`.
///
/// # Arguments
///
/// * `duration` - The [`Duration`] to format.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use jwt_debugger::utils::duration::format_duration_concise;
///
/// assert_eq!(format_duration_concise(Duration::from_secs(45)), "45s");
/// assert_eq!(format_duration_concise(Duration::from_secs(90)), "1m 30s");
/// assert_eq!(format_duration_concise(Duration::from_secs(3600)), "1h");
/// assert_eq!(format_duration_concise(Duration::from_secs(90000)), "1d 1h");
/// ```
pub fn format_duration_concise(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs == 0 {
        return "0s".to_string();
    }

    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if seconds > 0 && days == 0 && hours == 0 {
        parts.push(format!("{seconds}s"));
    }

    if parts.is_empty() {
        "0s".to_string()
    } else {
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
    }

    #[test]
    fn test_format_duration_concise() {
        assert_eq!(format_duration_concise(Duration::from_secs(45)), "45s");
        assert_eq!(format_duration_concise(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration_concise(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration_concise(Duration::from_secs(90000)), "1d 1h");
    }
}
