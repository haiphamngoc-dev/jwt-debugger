//! Validation of registered and custom JWT claims against temporal constraints and business policies.

use chrono::{DateTime, Utc};
use std::time::Duration;

use crate::domain::claims::StandardClaims;
use crate::domain::error::ClaimValidationError;
use crate::domain::verification::{ClaimCheckStatus, ClaimValidationReport};
use crate::utils::time::format_relative_time;

/// Options and constraints for validating JWT claims.
#[derive(Debug, Clone, Default)]
pub struct ClaimValidationOptions {
    /// Expected issuer identifier (`iss`).
    pub issuer: Option<String>,
    /// Expected audience identifier (`aud`).
    pub audience: Option<String>,
    /// Expected subject identifier (`sub`).
    pub subject: Option<String>,
    /// Allowed clock skew / leeway duration.
    pub leeway: Duration,
    /// If `true`, reject tokens missing the `exp` claim.
    pub require_exp: bool,
    /// If `true`, reject tokens missing the `iat` claim.
    pub require_iat: bool,
    /// If `true`, reject tokens missing the `nbf` claim.
    pub require_nbf: bool,
}

/// Validates standard registered claims (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`) against validation options and reference time.
///
/// # Arguments
///
/// * `claims` - The parsed registered and custom claims.
/// * `options` - Policy constraints including expected issuer, audience, and clock leeway.
/// * `now` - Reference current time for temporal checks.
///
/// # Returns
///
/// Returns a detailed [`ClaimValidationReport`] containing status per claim and any validation errors.
///
/// # Examples
///
/// ```
/// use chrono::Utc;
/// use jwt_debugger::application::{ClaimValidationOptions, validate_claims};
/// use jwt_debugger::domain::StandardClaims;
///
/// let claims = StandardClaims::from_json_value(&serde_json::json!({
///     "exp": 1700000000
/// }));
/// let options = ClaimValidationOptions::default();
/// let report = validate_claims(&claims, &options, Utc::now());
/// ```
pub fn validate_claims(
    claims: &StandardClaims,
    options: &ClaimValidationOptions,
    now: DateTime<Utc>,
) -> ClaimValidationReport {
    let mut report = ClaimValidationReport::default();
    let mut errors = Vec::new();
    let now_ts = now.timestamp();
    let leeway_secs = options.leeway.as_secs() as i64;

    // 1. Expiration (exp)
    if let Some(exp) = claims.exp {
        let exp_with_leeway = exp.saturating_add(leeway_secs);
        if now_ts > exp_with_leeway {
            let exp_dt = DateTime::from_timestamp(exp, 0).unwrap_or(now);
            let rel = format_relative_time(exp_dt, now);
            let formatted_utc = exp_dt.format("%Y-%m-%d %H:%M:%S UTC").to_string();
            errors.push(ClaimValidationError::Expired {
                expired_at: formatted_utc,
                relative: rel,
            });
            report.expiration = ClaimCheckStatus::Invalid;
        } else {
            report.expiration = ClaimCheckStatus::Valid;
        }
    } else if options.require_exp {
        errors.push(ClaimValidationError::MissingRequiredClaim(
            "exp".to_string(),
        ));
        report.expiration = ClaimCheckStatus::Missing;
    }

    // 2. Not Before (nbf)
    if let Some(nbf) = claims.nbf {
        let nbf_with_leeway = nbf.saturating_sub(leeway_secs);
        if now_ts < nbf_with_leeway {
            let nbf_dt = DateTime::from_timestamp(nbf, 0).unwrap_or(now);
            let rel = format_relative_time(nbf_dt, now);
            let formatted_utc = nbf_dt.format("%Y-%m-%d %H:%M:%S UTC").to_string();
            errors.push(ClaimValidationError::NotYetValid {
                nbf: formatted_utc,
                relative: rel,
            });
            report.not_before = ClaimCheckStatus::Invalid;
        } else {
            report.not_before = ClaimCheckStatus::Valid;
        }
    } else if options.require_nbf {
        errors.push(ClaimValidationError::MissingRequiredClaim(
            "nbf".to_string(),
        ));
        report.not_before = ClaimCheckStatus::Missing;
    }

    // 3. Issued At (iat)
    if let Some(iat) = claims.iat {
        let iat_with_leeway = iat.saturating_sub(leeway_secs);
        if now_ts < iat_with_leeway {
            let iat_dt = DateTime::from_timestamp(iat, 0).unwrap_or(now);
            let rel = format_relative_time(iat_dt, now);
            let formatted_utc = iat_dt.format("%Y-%m-%d %H:%M:%S UTC").to_string();
            errors.push(ClaimValidationError::FutureIssuedAt {
                iat: formatted_utc,
                relative: rel,
            });
            report.issued_at = ClaimCheckStatus::Invalid;
        } else {
            report.issued_at = ClaimCheckStatus::Valid;
        }
    } else if options.require_iat {
        errors.push(ClaimValidationError::MissingRequiredClaim(
            "iat".to_string(),
        ));
        report.issued_at = ClaimCheckStatus::Missing;
    }

    // 4. Issuer (iss)
    if let Some(ref expected_iss) = options.issuer {
        if let Some(ref token_iss) = claims.iss {
            if token_iss == expected_iss {
                report.issuer = ClaimCheckStatus::Valid;
            } else {
                errors.push(ClaimValidationError::IssuerMismatch {
                    expected: expected_iss.clone(),
                    actual: token_iss.clone(),
                });
                report.issuer = ClaimCheckStatus::Invalid;
            }
        } else {
            errors.push(ClaimValidationError::MissingRequiredClaim(
                "iss".to_string(),
            ));
            report.issuer = ClaimCheckStatus::Missing;
        }
    }

    // 5. Audience (aud)
    if let Some(ref expected_aud) = options.audience {
        if let Some(ref token_aud) = claims.aud {
            if token_aud.contains(expected_aud) {
                report.audience = ClaimCheckStatus::Valid;
            } else {
                errors.push(ClaimValidationError::AudienceMismatch {
                    expected: expected_aud.clone(),
                    actual: token_aud.to_string(),
                });
                report.audience = ClaimCheckStatus::Invalid;
            }
        } else {
            errors.push(ClaimValidationError::MissingRequiredClaim(
                "aud".to_string(),
            ));
            report.audience = ClaimCheckStatus::Missing;
        }
    }

    // 6. Subject (sub)
    if let Some(ref expected_sub) = options.subject {
        if let Some(ref token_sub) = claims.sub {
            if token_sub == expected_sub {
                report.subject = ClaimCheckStatus::Valid;
            } else {
                errors.push(ClaimValidationError::SubjectMismatch {
                    expected: expected_sub.clone(),
                    actual: token_sub.clone(),
                });
                report.subject = ClaimCheckStatus::Invalid;
            }
        } else {
            errors.push(ClaimValidationError::MissingRequiredClaim(
                "sub".to_string(),
            ));
            report.subject = ClaimCheckStatus::Missing;
        }
    }

    // Overall status
    if !errors.is_empty() {
        report.status = ClaimCheckStatus::Invalid;
    } else if report.expiration == ClaimCheckStatus::Valid
        || report.not_before == ClaimCheckStatus::Valid
        || report.issued_at == ClaimCheckStatus::Valid
        || report.issuer == ClaimCheckStatus::Valid
        || report.audience == ClaimCheckStatus::Valid
        || report.subject == ClaimCheckStatus::Valid
    {
        report.status = ClaimCheckStatus::Valid;
    } else {
        report.status = ClaimCheckStatus::NotChecked;
    }

    report.errors = errors;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expiration_validation() {
        let now = DateTime::from_timestamp(1700000000, 0).unwrap();
        let mut claims = StandardClaims::from_json_value(&serde_json::json!({
            "exp": 1699990000 // Expired
        }));

        let opts = ClaimValidationOptions::default();
        let report = validate_claims(&claims, &opts, now);
        assert_eq!(report.status, ClaimCheckStatus::Invalid);
        assert_eq!(report.expiration, ClaimCheckStatus::Invalid);

        // With leeway
        claims.exp = Some(1699999990); // 10s expired
        let opts_leeway = ClaimValidationOptions {
            leeway: Duration::from_secs(30),
            ..Default::default()
        };
        let report_leeway = validate_claims(&claims, &opts_leeway, now);
        assert_eq!(report_leeway.expiration, ClaimCheckStatus::Valid);
    }

    #[test]
    fn test_audience_validation() {
        let now = DateTime::from_timestamp(1700000000, 0).unwrap();
        let claims = StandardClaims::from_json_value(&serde_json::json!({
            "aud": ["api", "mobile"]
        }));

        let opts = ClaimValidationOptions {
            audience: Some("api".to_string()),
            ..Default::default()
        };
        let report = validate_claims(&claims, &opts, now);
        assert_eq!(report.audience, ClaimCheckStatus::Valid);

        let opts_bad = ClaimValidationOptions {
            audience: Some("web".to_string()),
            ..Default::default()
        };
        let report_bad = validate_claims(&claims, &opts_bad, now);
        assert_eq!(report_bad.audience, ClaimCheckStatus::Invalid);
    }
}
