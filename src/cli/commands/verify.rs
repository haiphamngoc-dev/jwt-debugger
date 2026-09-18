//! Command handler for `verify`.

use anyhow::Result;
use chrono::Utc;
use std::str::FromStr;

use crate::application::validate_claims::ClaimValidationOptions;
use crate::application::verify::verify_jwt;
use crate::cli::args::VerifyArgs;
use crate::cli::exit_codes::CliExit;
use crate::cli::formatting::Formatter;
use crate::crypto::keys::{HmacKey, SecretEncoding, VerificationKey};
use crate::crypto::verifier::VerificationOptions;
use crate::domain::algorithm::JwtAlgorithm;
use crate::domain::jwt::JwtToken;
use crate::domain::verification::{ClaimCheckStatus, SignatureStatus};
use crate::infrastructure::filesystem::read_file_to_string;
use crate::infrastructure::jwks_http::{JwksFetchOptions, fetch_remote_jwks};
use crate::jwk::converter::jwk_to_verification_key;
use crate::jwk::parser::{parse_jwk, parse_jwks};
use crate::jwk::selector::select_jwk;
use crate::utils::duration::parse_duration;

/// Executes the `verify` command, validating cryptographic signature and claim constraints.
///
/// # Arguments
///
/// * `args` - Parsed verify command options.
/// * `fmt` - Terminal formatter for colors and styling.
/// * `quiet` - If `true`, suppresses stdout on success.
///
/// # Errors
///
/// Returns an error if token resolution or key parsing fails with unhandled errors.
pub fn execute(args: &VerifyArgs, fmt: &Formatter, quiet: bool) -> Result<CliExit> {
    let raw_token = args.input.resolve_token()?;
    let token = match JwtToken::parse(&raw_token) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{}: {err}", fmt.invalid("Error parsing JWT"));
            return Ok(CliExit::MalformedJwt);
        }
    };

    let expected_alg = match JwtAlgorithm::from_str(&args.alg) {
        Ok(alg) => alg,
        Err(err) => {
            eprintln!("{}: {err}", fmt.invalid("Invalid algorithm"));
            return Ok(CliExit::InvalidUsage);
        }
    };

    let leeway = match parse_duration(&args.leeway) {
        Ok(d) => d,
        Err(err) => {
            eprintln!("{}: {err}", fmt.invalid("Invalid leeway"));
            return Ok(CliExit::InvalidUsage);
        }
    };

    let timeout = match parse_duration(&args.timeout) {
        Ok(d) => d,
        Err(err) => {
            eprintln!("{}: {err}", fmt.invalid("Invalid timeout"));
            return Ok(CliExit::InvalidUsage);
        }
    };

    // Resolve VerificationKey
    let key = match resolve_key(args, expected_alg, &token, timeout) {
        Ok(k) => k,
        Err(exit) => return Ok(exit),
    };

    let ver_options = VerificationOptions {
        allow_unsecured: args.allow_unsecured,
    };

    let claim_options = ClaimValidationOptions {
        issuer: args.issuer.clone(),
        audience: args.audience.clone(),
        subject: args.subject.clone(),
        leeway,
        require_exp: args.require_exp,
        require_iat: args.require_iat,
        require_nbf: args.require_nbf,
    };

    let report = verify_jwt(
        &token,
        expected_alg,
        &key,
        &ver_options,
        &claim_options,
        Utc::now(),
    );

    if args.json {
        let json_str = serde_json::to_string_pretty(&report)?;
        println!("{json_str}");
    } else if !quiet {
        println!("{}", fmt.title("JWT Verification Report\n"));

        // Signature section
        println!("{}", fmt.section("Signature"));
        match report.signature.status {
            SignatureStatus::Valid => {
                println!("{}", fmt.key_val("Status:", &fmt.valid("VALID")));
            }
            SignatureStatus::Invalid => {
                println!("{}", fmt.key_val("Status:", &fmt.invalid("INVALID")));
                if let Some(ref err) = report.signature.error {
                    println!("{}", fmt.key_val("Reason:", err));
                }
            }
            SignatureStatus::Unsecured => {
                println!(
                    "{}",
                    fmt.key_val("Status:", &fmt.warning("UNSECURED (alg=none)"))
                );
            }
            SignatureStatus::NotPerformed => {
                println!("{}", fmt.key_val("Status:", &fmt.warning("NOT PERFORMED")));
            }
        }
        if let Some(alg) = report.signature.algorithm {
            println!("{}", fmt.key_val("Algorithm:", &alg.to_string()));
        }
        if let Some(ref kt) = report.signature.key_type {
            println!("{}", fmt.key_val("Key Type:", kt));
        }
        println!();

        // Claims section
        println!("{}", fmt.section("Claims"));
        println!(
            "{}",
            fmt.key_val(
                "Overall Claims:",
                &format_claim_status(report.claims.status, fmt)
            )
        );
        if report.claims.expiration != ClaimCheckStatus::NotChecked {
            println!(
                "{}",
                fmt.key_val(
                    "Expiration (exp):",
                    &format_claim_status(report.claims.expiration, fmt)
                )
            );
        }
        if report.claims.not_before != ClaimCheckStatus::NotChecked {
            println!(
                "{}",
                fmt.key_val(
                    "Not Before (nbf):",
                    &format_claim_status(report.claims.not_before, fmt)
                )
            );
        }
        if report.claims.issued_at != ClaimCheckStatus::NotChecked {
            println!(
                "{}",
                fmt.key_val(
                    "Issued At (iat):",
                    &format_claim_status(report.claims.issued_at, fmt)
                )
            );
        }
        if report.claims.issuer != ClaimCheckStatus::NotChecked {
            println!(
                "{}",
                fmt.key_val(
                    "Issuer (iss):",
                    &format_claim_status(report.claims.issuer, fmt)
                )
            );
        }
        if report.claims.audience != ClaimCheckStatus::NotChecked {
            println!(
                "{}",
                fmt.key_val(
                    "Audience (aud):",
                    &format_claim_status(report.claims.audience, fmt)
                )
            );
        }
        if report.claims.subject != ClaimCheckStatus::NotChecked {
            println!(
                "{}",
                fmt.key_val(
                    "Subject (sub):",
                    &format_claim_status(report.claims.subject, fmt)
                )
            );
        }

        if !report.claims.errors.is_empty() {
            println!("\n{}", fmt.invalid("Claim Errors:"));
            for err in &report.claims.errors {
                println!("- {err}");
            }
        }
        println!();

        // Final result
        println!("{}", fmt.section("Result"));
        if report.valid {
            println!("{}", fmt.valid("VERIFICATION SUCCESSFUL: JWT is VALID"));
        } else {
            println!("{}", fmt.invalid("VERIFICATION FAILED: JWT is INVALID"));
        }
    }

    if report.valid {
        Ok(CliExit::Success)
    } else if report.signature.status == SignatureStatus::Invalid {
        Ok(CliExit::SignatureInvalid)
    } else {
        Ok(CliExit::ClaimsInvalid)
    }
}

fn format_claim_status(status: ClaimCheckStatus, fmt: &Formatter) -> String {
    match status {
        ClaimCheckStatus::Valid => fmt.valid("VALID"),
        ClaimCheckStatus::Invalid => fmt.invalid("INVALID"),
        ClaimCheckStatus::Missing => fmt.invalid("MISSING"),
        ClaimCheckStatus::NotChecked => fmt.muted("NOT CHECKED"),
    }
}

fn resolve_key(
    args: &VerifyArgs,
    expected_alg: JwtAlgorithm,
    token: &JwtToken,
    timeout: std::time::Duration,
) -> Result<VerificationKey, CliExit> {
    // 1. Unsecured alg=none
    if expected_alg == JwtAlgorithm::None {
        if !args.allow_unsecured {
            eprintln!(
                "Error: Unsecured JWT (alg=none) is not accepted for verification without --allow-unsecured"
            );
            return Err(CliExit::InvalidUsage);
        }
        return Ok(VerificationKey::Unsecured);
    }

    // 2. HMAC Secrets
    if let Some(ref secret) = args.secret {
        return HmacKey::from_encoded(secret, SecretEncoding::Utf8)
            .map(VerificationKey::Hmac)
            .map_err(|e| {
                eprintln!("Key Error: {e}");
                CliExit::KeyError
            });
    }
    if let Some(ref path) = args.secret_file {
        let content = read_file_to_string(path).map_err(|e| {
            eprintln!("Key Error: Failed to read secret file: {e}");
            CliExit::KeyError
        })?;
        return HmacKey::from_encoded(&content, SecretEncoding::Utf8)
            .map(VerificationKey::Hmac)
            .map_err(|e| {
                eprintln!("Key Error: {e}");
                CliExit::KeyError
            });
    }
    if let Some(ref hex_s) = args.secret_hex {
        return HmacKey::from_encoded(hex_s, SecretEncoding::Hex)
            .map(VerificationKey::Hmac)
            .map_err(|e| {
                eprintln!("Key Error: {e}");
                CliExit::KeyError
            });
    }
    if let Some(ref b64_s) = args.secret_base64 {
        return HmacKey::from_encoded(b64_s, SecretEncoding::Base64)
            .map(VerificationKey::Hmac)
            .map_err(|e| {
                eprintln!("Key Error: {e}");
                CliExit::KeyError
            });
    }
    if let Some(ref b64url_s) = args.secret_base64url {
        return HmacKey::from_encoded(b64url_s, SecretEncoding::Base64Url)
            .map(VerificationKey::Hmac)
            .map_err(|e| {
                eprintln!("Key Error: {e}");
                CliExit::KeyError
            });
    }

    // 3. PEM Public Key
    if let Some(ref path) = args.public_key {
        let pem_str = read_file_to_string(path).map_err(|e| {
            eprintln!("Key Error: Failed to read public key file: {e}");
            CliExit::KeyError
        })?;
        return VerificationKey::from_pem(&pem_str).map_err(|e| {
            eprintln!("Key Error: {e}");
            CliExit::KeyError
        });
    }

    // 4. Local JWK
    if let Some(ref path) = args.jwk {
        let json_str = read_file_to_string(path).map_err(|e| {
            eprintln!("Key Error: Failed to read JWK file: {e}");
            CliExit::KeyError
        })?;
        let jwk = parse_jwk(&json_str).map_err(|e| {
            eprintln!("Key Error: {e}");
            CliExit::KeyError
        })?;
        return jwk_to_verification_key(&jwk).map_err(|e| {
            eprintln!("Key Error: {e}");
            CliExit::KeyError
        });
    }

    // 5. Local JWKS
    if let Some(ref path) = args.jwks {
        let json_str = read_file_to_string(path).map_err(|e| {
            eprintln!("Key Error: Failed to read JWKS file: {e}");
            CliExit::KeyError
        })?;
        let jwks = parse_jwks(&json_str).map_err(|e| {
            eprintln!("Key Error: {e}");
            CliExit::KeyError
        })?;
        return select_jwk(&jwks, token.header.kid.as_deref(), expected_alg).map_err(|e| {
            eprintln!("Key Error: {e}");
            CliExit::KeyError
        });
    }

    // 6. Remote JWKS
    if let Some(ref url) = args.jwks_url {
        let fetch_opts = JwksFetchOptions {
            timeout,
            allow_insecure_http: args.allow_insecure_http,
        };
        let jwks = fetch_remote_jwks(url, &fetch_opts).map_err(|e| {
            eprintln!("JWKS Error: {e}");
            CliExit::NetworkError
        })?;
        return select_jwk(&jwks, token.header.kid.as_deref(), expected_alg).map_err(|e| {
            eprintln!("JWKS Error: {e}");
            CliExit::KeyError
        });
    }

    eprintln!(
        "Error: No verification key provided. Specify --secret, --secret-file, --public-key, --jwk, --jwks, or --jwks-url."
    );
    Err(CliExit::InvalidUsage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::TokenInputArgs;
    use crate::cli::formatting::ColorChoice;

    #[test]
    fn test_verify_command_hs256() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let args = VerifyArgs {
            input: TokenInputArgs {
                token_arg: Some(raw.to_string()),
                ..Default::default()
            },
            alg: "HS256".to_string(),
            secret: Some("your-256-bit-secret".to_string()),
            secret_file: None,
            secret_hex: None,
            secret_base64: None,
            secret_base64url: None,
            public_key: None,
            jwk: None,
            jwks: None,
            jwks_url: None,
            issuer: None,
            audience: None,
            subject: None,
            leeway: "0s".to_string(),
            require_exp: false,
            require_iat: false,
            require_nbf: false,
            allow_unsecured: false,
            timeout: "5s".to_string(),
            allow_insecure_http: false,
            json: true,
        };
        let fmt = Formatter::new(ColorChoice::Never);
        let res = execute(&args, &fmt, false).unwrap();
        assert_eq!(res, CliExit::Success);
    }
}
