//! Comprehensive JWT token inspection providing structural, timing, signature metadata, and security analysis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::domain::jwt::JwtToken;
use crate::domain::verification::SecurityWarning;
use crate::utils::duration::format_duration_concise;
use crate::utils::time::{FormattedTimestamp, TimezoneOption};

/// Temporal inspection details including timestamps, relative durations, token age, and expiration status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingInspection {
    /// Formatted issued-at (`iat`) timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<FormattedTimestamp>,
    /// Formatted expiration (`exp`) timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<FormattedTimestamp>,
    /// Formatted not-before (`nbf`) timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<FormattedTimestamp>,
    /// Elapsed duration since token issuance (e.g. `"5m 30s"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age: Option<String>,
    /// Total configured lifetime between `iat` and `exp` (e.g. `"1h"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<String>,
    /// Remaining time until token expiration (e.g. `"24m"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<String>,
    /// Whether the token is currently expired relative to the inspection time.
    pub is_expired: bool,
}

/// Structural properties and byte sizing of the token segments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureInspection {
    /// Number of dot-separated segments in the token.
    pub segments: usize,
    /// Serialization format description (e.g. `"JWS Compact Serialization"`).
    pub format: String,
    /// Total byte size of the raw token string.
    pub total_bytes: usize,
    /// Decoded header size in bytes.
    pub header_bytes: usize,
    /// Decoded payload size in bytes.
    pub payload_bytes: usize,
    /// Decoded cryptographic signature size in bytes.
    pub signature_bytes: usize,
}

/// Signature metadata identified during inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInspection {
    /// Algorithm declared in the header (e.g. `"HS256"`, `"RS256"`, `"none"`).
    pub algorithm: String,
    /// Signature byte length.
    pub signature_size_bytes: usize,
    /// High-level verification indicator (e.g. `"NOT PERFORMED"`).
    pub verification: String,
}

/// Comprehensive inspection report containing token structure, claims, timing, and security warnings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionReport {
    /// Token structural analysis.
    pub structure: StructureInspection,
    /// Parsed JOSE header as JSON.
    pub header: serde_json::Value,
    /// Parsed payload claims as JSON.
    pub payload: serde_json::Value,
    /// Temporal inspection and timestamps.
    pub timing: TimingInspection,
    /// Signature segment metadata.
    pub signature: SignatureInspection,
    /// Potential security vulnerabilities or hygiene warnings.
    pub warnings: Vec<SecurityWarning>,
}

/// Inspects a [`JwtToken`] and generates a detailed [`InspectionReport`] with structural, timing, and security analysis.
///
/// # Arguments
///
/// * `token` - The parsed JWT token to inspect.
/// * `tz` - Timezone formatting preference for timestamp displays.
/// * `now` - Reference current UTC time for temporal calculations.
///
/// # Examples
///
/// ```
/// use chrono::Utc;
/// use jwt_debugger::application::inspect_jwt;
/// use jwt_debugger::domain::JwtToken;
/// use jwt_debugger::utils::time::TimezoneOption;
///
/// let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2ln";
/// let token = JwtToken::parse(raw).unwrap();
/// let report = inspect_jwt(&token, &TimezoneOption::Utc, Utc::now());
///
/// assert_eq!(report.structure.segments, 3);
/// assert_eq!(report.signature.algorithm, "HS256");
/// ```
pub fn inspect_jwt(token: &JwtToken, tz: &TimezoneOption, now: DateTime<Utc>) -> InspectionReport {
    let now_ts = now.timestamp();

    // 1. Structure
    let structure = StructureInspection {
        segments: 3,
        format: "JWS Compact Serialization".to_string(),
        total_bytes: token.raw.len(),
        header_bytes: token.header_bytes.len(),
        payload_bytes: token.payload_bytes.len(),
        signature_bytes: token.signature_bytes.len(),
    };

    // 2. Timing
    let iat_fmt = token
        .claims
        .iat
        .map(|ts| FormattedTimestamp::from_unix(ts, tz, now));
    let exp_fmt = token
        .claims
        .exp
        .map(|ts| FormattedTimestamp::from_unix(ts, tz, now));
    let nbf_fmt = token
        .claims
        .nbf
        .map(|ts| FormattedTimestamp::from_unix(ts, tz, now));

    let age = token.claims.iat.and_then(|iat| {
        let diff = now_ts - iat;
        if diff >= 0 {
            Some(format_duration_concise(Duration::from_secs(diff as u64)))
        } else {
            None
        }
    });

    let lifetime = match (token.claims.iat, token.claims.exp) {
        (Some(iat), Some(exp)) if exp >= iat => Some(format_duration_concise(Duration::from_secs(
            (exp - iat) as u64,
        ))),
        _ => None,
    };

    let expires_in = token.claims.exp.and_then(|exp| {
        let diff = exp - now_ts;
        if diff > 0 {
            Some(format_duration_concise(Duration::from_secs(diff as u64)))
        } else {
            None
        }
    });

    let is_expired = token.claims.exp.is_some_and(|exp| now_ts > exp);

    let timing = TimingInspection {
        issued_at: iat_fmt,
        expires_at: exp_fmt,
        not_before: nbf_fmt,
        age,
        lifetime,
        expires_in,
        is_expired,
    };

    // 3. Signature
    let signature = SignatureInspection {
        algorithm: token.header.alg.clone(),
        signature_size_bytes: token.signature_bytes.len(),
        verification: "NOT PERFORMED".to_string(),
    };

    // 4. Warnings
    let mut warnings = Vec::new();

    if token.header.alg.eq_ignore_ascii_case("none") {
        warnings.push(SecurityWarning {
            code: "UNSECURED_ALGORITHM".to_string(),
            message:
                "Token specifies 'alg: none' (unsecured token with no cryptographic signature)."
                    .to_string(),
        });
    }

    if token.claims.exp.is_none() {
        warnings.push(SecurityWarning {
            code: "MISSING_EXPIRATION".to_string(),
            message: "Token has no expiration ('exp') claim and will never expire automatically."
                .to_string(),
        });
    }

    if let (Some(iat), Some(exp)) = (token.claims.iat, token.claims.exp) {
        let duration_secs = exp.saturating_sub(iat);
        if duration_secs > 30 * 86400 {
            let dur_str = format_duration_concise(Duration::from_secs(duration_secs as u64));
            warnings.push(SecurityWarning {
                code: "LONG_LIFETIME".to_string(),
                message: format!("Token lifetime is unusually long ({dur_str})."),
            });
        }
    }

    if let Some(iat) = token.claims.iat
        && iat > now_ts + 60
    {
        warnings.push(SecurityWarning {
            code: "FUTURE_IAT".to_string(),
            message: "Token issued-at ('iat') timestamp is in the future.".to_string(),
        });
    }

    if let Some(nbf) = token.claims.nbf
        && nbf > now_ts + 60
    {
        warnings.push(SecurityWarning {
            code: "FUTURE_NBF".to_string(),
            message: "Token not-before ('nbf') timestamp is in the future.".to_string(),
        });
    }

    if let Some(ref typ) = token.header.typ
        && typ != "JWT"
        && typ != "jwt"
    {
        warnings.push(SecurityWarning {
            code: "UNUSUAL_TYPE".to_string(),
            message: format!("Header 'typ' is '{typ}' (standard is 'JWT')."),
        });
    }

    if token.raw.len() > 8 * 1024 {
        warnings.push(SecurityWarning {
            code: "LARGE_TOKEN".to_string(),
            message: format!("Token size is unusually large ({} bytes).", token.raw.len()),
        });
    }

    InspectionReport {
        structure,
        header: token.header_json.clone(),
        payload: token.payload_json.clone(),
        timing,
        signature,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_jwt_structure_and_warnings() {
        let raw = "eyJhbGciOiJub25lIiwidHlwIjoiQ1VTVE9NIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.";
        let token = JwtToken::parse(raw).unwrap();
        let now = DateTime::from_timestamp(1700000000, 0).unwrap();

        let report = inspect_jwt(&token, &TimezoneOption::Utc, now);

        assert_eq!(report.structure.segments, 3);
        assert_eq!(report.signature.algorithm, "none");
        assert_eq!(report.signature.signature_size_bytes, 0);

        let warning_codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
        assert!(warning_codes.contains(&"UNSECURED_ALGORITHM"));
        assert!(warning_codes.contains(&"MISSING_EXPIRATION"));
        assert!(warning_codes.contains(&"UNUSUAL_TYPE"));
    }

    #[test]
    fn test_inspect_jwt_timing() {
        // iat = 1700000000, exp = 1700003600 (1h lifetime)
        // now = 1700001800 (30m age, 30m remaining)
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMzYwMH0.c2ln";
        let token = JwtToken::parse(raw).unwrap();
        let now = DateTime::from_timestamp(1700001800, 0).unwrap();

        let report = inspect_jwt(&token, &TimezoneOption::Utc, now);

        assert_eq!(report.timing.age.as_deref(), Some("30m"));
        assert_eq!(report.timing.lifetime.as_deref(), Some("1h"));
        assert_eq!(report.timing.expires_in.as_deref(), Some("30m"));
        assert!(!report.timing.is_expired);
    }
}
