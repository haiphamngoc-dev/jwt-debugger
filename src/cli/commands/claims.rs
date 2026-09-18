//! Command handler for `claims`.

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::cli::args::ClaimsArgs;
use crate::cli::exit_codes::CliExit;
use crate::cli::formatting::Formatter;
use crate::domain::jwt::JwtToken;
use crate::utils::duration::format_duration_concise;
use crate::utils::time::{FormattedTimestamp, TimezoneOption};

/// Complete claims analysis report for CLI JSON output.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimsAnalysisReport {
    /// Standard registered claims mapped to JSON.
    pub standard_claims: serde_json::Value,
    /// Custom claims map.
    pub custom_claims: serde_json::Map<String, serde_json::Value>,
    /// Formatted issued-at timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<FormattedTimestamp>,
    /// Formatted expiration timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<FormattedTimestamp>,
    /// Formatted not-before timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<FormattedTimestamp>,
    /// Whether the token is expired.
    pub is_expired: bool,
    /// Time remaining until expiration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<String>,
    /// Elapsed age of the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age: Option<String>,
}

/// Executes the `claims` command, analyzing and displaying standard and custom claims.
///
/// # Arguments
///
/// * `args` - Parsed claims command options.
/// * `fmt` - Terminal formatter for colors and styling.
/// * `quiet` - If `true`, suppresses stdout on success.
///
/// # Errors
///
/// Returns an error if token resolution or JSON serialization fails.
pub fn execute(args: &ClaimsArgs, fmt: &Formatter, quiet: bool) -> Result<CliExit> {
    let raw_token = args.input.resolve_token()?;
    let token = match JwtToken::parse(&raw_token) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{}: {err}", fmt.invalid("Error parsing JWT"));
            return Ok(CliExit::MalformedJwt);
        }
    };

    let tz = match TimezoneOption::from_str(&args.timezone) {
        Ok(tz) => tz,
        Err(err) => {
            eprintln!("{}: {err}", fmt.invalid("Invalid timezone"));
            return Ok(CliExit::InvalidUsage);
        }
    };

    let now = Utc::now();
    let now_ts = now.timestamp();

    let iat_fmt = token
        .claims
        .iat
        .map(|ts| FormattedTimestamp::from_unix(ts, &tz, now));
    let exp_fmt = token
        .claims
        .exp
        .map(|ts| FormattedTimestamp::from_unix(ts, &tz, now));
    let nbf_fmt = token
        .claims
        .nbf
        .map(|ts| FormattedTimestamp::from_unix(ts, &tz, now));

    let is_expired = token.claims.exp.is_some_and(|exp| now_ts > exp);

    let age = token.claims.iat.and_then(|iat| {
        let diff = now_ts - iat;
        if diff >= 0 {
            Some(format_duration_concise(std::time::Duration::from_secs(
                diff as u64,
            )))
        } else {
            None
        }
    });

    let expires_in = token.claims.exp.and_then(|exp| {
        let diff = exp - now_ts;
        if diff > 0 {
            Some(format_duration_concise(std::time::Duration::from_secs(
                diff as u64,
            )))
        } else {
            None
        }
    });

    let report = ClaimsAnalysisReport {
        standard_claims: serde_json::to_value(&token.claims)?,
        custom_claims: token.claims.custom.clone(),
        issued_at: iat_fmt,
        expires_at: exp_fmt,
        not_before: nbf_fmt,
        is_expired,
        expires_in,
        age,
    };

    if args.json {
        let json_str = serde_json::to_string_pretty(&report)?;
        println!("{json_str}");
        return Ok(CliExit::Success);
    }

    if !quiet {
        println!("{}", fmt.title("JWT Claims Analysis\n"));

        // Expiration
        if let Some(exp) = token.claims.exp {
            println!("{}", fmt.section("Expiration (exp)"));
            println!("{}", fmt.key_val("exp (unix):", &exp.to_string()));
            if let Some(ref exp_ts) = report.expires_at {
                println!("{}", fmt.key_val("Time:", &exp_ts.formatted));
                println!("{}", fmt.key_val("UTC:", &exp_ts.utc));
            }
            if report.is_expired {
                println!("{}", fmt.key_val("Status:", &fmt.invalid("EXPIRED")));
                if let Some(ref exp_ts) = report.expires_at {
                    println!("{}", fmt.key_val("Expired:", &exp_ts.relative));
                }
            } else {
                println!("{}", fmt.key_val("Status:", &fmt.valid("ACTIVE")));
                if let Some(ref exp_in) = report.expires_in {
                    println!("{}", fmt.key_val("Expires in:", exp_in));
                }
            }
            println!();
        }

        // Issued At
        if let Some(iat) = token.claims.iat {
            println!("{}", fmt.section("Issued At (iat)"));
            println!("{}", fmt.key_val("iat (unix):", &iat.to_string()));
            if let Some(ref iat_ts) = report.issued_at {
                println!("{}", fmt.key_val("Time:", &iat_ts.formatted));
                println!("{}", fmt.key_val("UTC:", &iat_ts.utc));
            }
            if let Some(ref age_str) = report.age {
                println!("{}", fmt.key_val("Age:", age_str));
            }
            println!();
        }

        // Not Before
        if let Some(nbf) = token.claims.nbf {
            println!("{}", fmt.section("Not Before (nbf)"));
            println!("{}", fmt.key_val("nbf (unix):", &nbf.to_string()));
            if let Some(ref nbf_ts) = report.not_before {
                println!("{}", fmt.key_val("Time:", &nbf_ts.formatted));
                println!("{}", fmt.key_val("UTC:", &nbf_ts.utc));
            }
            if now_ts < nbf {
                println!("{}", fmt.key_val("Status:", &fmt.invalid("NOT YET ACTIVE")));
            } else {
                println!("{}", fmt.key_val("Status:", &fmt.valid("ACTIVE")));
            }
            println!();
        }

        // Standard Identity Claims
        if token.claims.iss.is_some()
            || token.claims.sub.is_some()
            || token.claims.aud.is_some()
            || token.claims.jti.is_some()
        {
            println!("{}", fmt.section("Identity Claims"));
            if let Some(ref iss) = token.claims.iss {
                println!("{}", fmt.key_val("Issuer (iss):", iss));
            }
            if let Some(ref sub) = token.claims.sub {
                println!("{}", fmt.key_val("Subject (sub):", sub));
            }
            if let Some(ref aud) = token.claims.aud {
                println!("{}", fmt.key_val("Audience (aud):", &aud.to_string()));
            }
            if let Some(ref jti) = token.claims.jti {
                println!("{}", fmt.key_val("JWT ID (jti):", jti));
            }
            println!();
        }

        // Custom Claims
        if !token.claims.custom.is_empty() {
            println!("{}", fmt.section("Custom Claims"));
            for (k, v) in &token.claims.custom {
                println!("{}", fmt.key_val(&format!("{k}:"), &v.to_string()));
            }
        }
    }

    Ok(CliExit::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::TokenInputArgs;
    use crate::cli::formatting::ColorChoice;

    #[test]
    fn test_claims_command_execution() {
        let raw = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig";
        let args = ClaimsArgs {
            input: TokenInputArgs {
                token_arg: Some(raw.to_string()),
                ..Default::default()
            },
            timezone: "UTC".to_string(),
            json: true,
        };
        let fmt = Formatter::new(ColorChoice::Never);
        let res = execute(&args, &fmt, false).unwrap();
        assert_eq!(res, CliExit::Success);
    }
}
