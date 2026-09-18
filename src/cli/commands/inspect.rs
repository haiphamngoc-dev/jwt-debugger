//! Command handler for `inspect`.

use anyhow::Result;
use chrono::Utc;
use std::str::FromStr;

use crate::application::inspect::inspect_jwt;
use crate::cli::args::InspectArgs;
use crate::cli::exit_codes::CliExit;
use crate::cli::formatting::Formatter;
use crate::domain::jwt::JwtToken;
use crate::utils::time::TimezoneOption;

/// Executes the `inspect` command, analyzing structure, timing, claims, signature, and security warnings.
///
/// # Arguments
///
/// * `args` - Parsed inspect command options.
/// * `fmt` - Terminal formatter for colors and styling.
/// * `quiet` - If `true`, suppresses stdout on success.
///
/// # Errors
///
/// Returns an error if token resolution or JSON serialization fails.
pub fn execute(args: &InspectArgs, fmt: &Formatter, quiet: bool) -> Result<CliExit> {
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

    let report = inspect_jwt(&token, &tz, Utc::now());

    if args.json {
        let json_str = serde_json::to_string_pretty(&report)?;
        println!("{json_str}");
        return Ok(CliExit::Success);
    }

    if !quiet {
        println!("{}", fmt.title("JWT Debugger - Inspect\n"));

        // Structure
        println!("{}", fmt.section("Structure"));
        println!(
            "{}",
            fmt.key_val("Segments:", &report.structure.segments.to_string())
        );
        println!("{}", fmt.key_val("Format:", &report.structure.format));
        println!(
            "{}",
            fmt.key_val(
                "Size:",
                &format!(
                    "{} bytes (header: {}, payload: {}, signature: {})",
                    report.structure.total_bytes,
                    report.structure.header_bytes,
                    report.structure.payload_bytes,
                    report.structure.signature_bytes
                )
            )
        );
        println!();

        // Header
        println!("{}", fmt.section("Header"));
        println!("{}", fmt.key_val("Algorithm:", &token.header.alg));
        if let Some(ref typ) = token.header.typ {
            println!("{}", fmt.key_val("Type:", typ));
        }
        if let Some(ref kid) = token.header.kid {
            println!("{}", fmt.key_val("Key ID:", kid));
        }
        for (k, v) in &token.header.extra {
            println!("{}", fmt.key_val(&format!("{k}:"), &v.to_string()));
        }
        println!();

        // Claims
        println!("{}", fmt.section("Claims"));
        if let Some(ref iss) = token.claims.iss {
            println!("{}", fmt.key_val("Issuer:", iss));
        }
        if let Some(ref sub) = token.claims.sub {
            println!("{}", fmt.key_val("Subject:", sub));
        }
        if let Some(ref aud) = token.claims.aud {
            println!("{}", fmt.key_val("Audience:", &aud.to_string()));
        }
        if let Some(ref iat) = report.timing.issued_at {
            println!("{}", fmt.key_val("Issued At:", &iat.formatted));
        }
        if let Some(ref exp) = report.timing.expires_at {
            let val = if report.timing.is_expired {
                format!("{} ({})", exp.formatted, fmt.invalid("EXPIRED"))
            } else {
                exp.formatted.clone()
            };
            println!("{}", fmt.key_val("Expires At:", &val));
        }
        if let Some(ref nbf) = report.timing.not_before {
            println!("{}", fmt.key_val("Not Before:", &nbf.formatted));
        }
        if let Some(ref jti) = token.claims.jti {
            println!("{}", fmt.key_val("JWT ID:", jti));
        }
        for (k, v) in &token.claims.custom {
            println!("{}", fmt.key_val(&format!("{k}:"), &v.to_string()));
        }
        println!();

        // Lifetime
        println!("{}", fmt.section("Lifetime"));
        if let Some(ref lt) = report.timing.lifetime {
            println!("{}", fmt.key_val("Token lifetime:", lt));
        }
        if let Some(ref age) = report.timing.age {
            println!("{}", fmt.key_val("Age:", age));
        }
        if let Some(ref exp_in) = report.timing.expires_in {
            println!("{}", fmt.key_val("Expires in:", exp_in));
        } else if report.timing.is_expired {
            println!("{}", fmt.key_val("Expires in:", &fmt.invalid("Expired")));
        }
        println!();

        // Signature
        println!("{}", fmt.section("Signature"));
        println!("{}", fmt.key_val("Algorithm:", &report.signature.algorithm));
        println!(
            "{}",
            fmt.key_val(
                "Signature bytes:",
                &report.signature.signature_size_bytes.to_string()
            )
        );
        println!(
            "{}",
            fmt.key_val(
                "Verification:",
                &fmt.warning(&report.signature.verification)
            )
        );
        println!();

        // Warnings
        println!("{}", fmt.section("Warnings"));
        if report.warnings.is_empty() {
            println!("{}", fmt.muted("None"));
        } else {
            for warn in &report.warnings {
                println!("- {}: {}", fmt.warning(&warn.code), warn.message);
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
    fn test_inspect_command_execution() {
        let raw = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig";
        let args = InspectArgs {
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
