//! Command handler for `jwk`.

use anyhow::Result;
use chrono::Utc;
use std::str::FromStr;

use crate::application::validate_claims::ClaimValidationOptions;
use crate::application::verify::verify_jwt;
use crate::cli::args::{JwkCommand, JwkSubcommands};
use crate::cli::exit_codes::CliExit;
use crate::cli::formatting::Formatter;
use crate::crypto::verifier::VerificationOptions;
use crate::domain::algorithm::JwtAlgorithm;
use crate::domain::jwt::JwtToken;
use crate::domain::verification::SignatureStatus;
use crate::infrastructure::filesystem::read_file_to_string;
use crate::jwk::converter::jwk_to_verification_key;
use crate::jwk::parser::{parse_jwk, parse_jwks};

/// Executes the `jwk` command and its subcommands (`inspect`, `verify`).
///
/// # Arguments
///
/// * `cmd` - Parsed JWK command and options.
/// * `fmt` - Terminal formatter for colors and styling.
/// * `quiet` - If `true`, suppresses stdout on success.
///
/// # Errors
///
/// Returns an error if file I/O, parsing, or JSON serialization fails.
pub fn execute(cmd: &JwkCommand, fmt: &Formatter, quiet: bool) -> Result<CliExit> {
    match &cmd.subcommand {
        JwkSubcommands::Inspect { file, json } => {
            let content = read_file_to_string(file).map_err(|e| {
                eprintln!("{}: {e}", fmt.invalid("Error reading file"));
                CliExit::GenericError
            });
            let content = match content {
                Ok(c) => c,
                Err(exit) => return Ok(exit),
            };

            // Try JWKS first, then JWK
            if let Ok(jwks) = parse_jwks(&content) {
                if *json {
                    println!("{}", serde_json::to_string_pretty(&jwks)?);
                } else if !quiet {
                    println!("{}", fmt.title("JSON Web Key Set (JWKS)"));
                    println!(
                        "{}",
                        fmt.key_val("Total Keys:", &jwks.keys.len().to_string())
                    );
                    println!();
                    for (i, key) in jwks.keys.iter().enumerate() {
                        println!("{}", fmt.section(&format!("Key #{}", i + 1)));
                        print_jwk_details(key, fmt);
                        println!();
                    }
                }
                return Ok(CliExit::Success);
            }

            match parse_jwk(&content) {
                Ok(jwk) => {
                    if *json {
                        println!("{}", serde_json::to_string_pretty(&jwk)?);
                    } else if !quiet {
                        println!("{}", fmt.title("JSON Web Key (JWK)"));
                        print_jwk_details(&jwk, fmt);
                    }
                    Ok(CliExit::Success)
                }
                Err(err) => {
                    eprintln!("{}: {err}", fmt.invalid("Error parsing JWK/JWKS"));
                    Ok(CliExit::GenericError)
                }
            }
        }

        JwkSubcommands::Verify {
            input,
            alg,
            jwk: jwk_file,
            json,
        } => {
            let raw_token = input.resolve_token()?;
            let token = match JwtToken::parse(&raw_token) {
                Ok(t) => t,
                Err(err) => {
                    eprintln!("{}: {err}", fmt.invalid("Error parsing JWT"));
                    return Ok(CliExit::MalformedJwt);
                }
            };

            let expected_alg = match JwtAlgorithm::from_str(alg) {
                Ok(a) => a,
                Err(err) => {
                    eprintln!("{}: {err}", fmt.invalid("Invalid algorithm"));
                    return Ok(CliExit::InvalidUsage);
                }
            };

            let content = match read_file_to_string(jwk_file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{}: {e}", fmt.invalid("Failed to read JWK file"));
                    return Ok(CliExit::KeyError);
                }
            };

            let jwk_key = match parse_jwk(&content) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("{}: {e}", fmt.invalid("Invalid JWK JSON"));
                    return Ok(CliExit::KeyError);
                }
            };

            let ver_key = match jwk_to_verification_key(&jwk_key) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("{}: {e}", fmt.invalid("JWK conversion error"));
                    return Ok(CliExit::KeyError);
                }
            };

            let ver_opts = VerificationOptions::default();
            let claim_opts = ClaimValidationOptions::default();
            let report = verify_jwt(
                &token,
                expected_alg,
                &ver_key,
                &ver_opts,
                &claim_opts,
                Utc::now(),
            );

            if *json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if !quiet {
                println!("{}", fmt.title("JWK Verification Result"));
                if report.valid {
                    println!("{}", fmt.valid("VALID: Signature verified successfully"));
                } else {
                    println!("{}", fmt.invalid("INVALID: Signature verification failed"));
                    if let Some(ref err) = report.signature.error {
                        println!("Reason: {err}");
                    }
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
    }
}

fn print_jwk_details(key: &crate::domain::jwk::JwkKey, fmt: &Formatter) {
    println!("{}", fmt.key_val("Key Type (kty):", &key.kty));
    if let Some(ref kid) = key.kid {
        println!("{}", fmt.key_val("Key ID (kid):", kid));
    }
    if let Some(ref use_) = key.key_use {
        println!("{}", fmt.key_val("Use (use):", use_));
    }
    if let Some(ref ops) = key.key_ops {
        println!("{}", fmt.key_val("Operations:", &ops.join(", ")));
    }
    if let Some(ref alg) = key.alg {
        println!("{}", fmt.key_val("Algorithm (alg):", alg));
    }
    if let Some(ref crv) = key.crv {
        println!("{}", fmt.key_val("Curve (crv):", crv));
    }
    if let Some(ref n) = key.n {
        println!(
            "{}",
            fmt.key_val("Modulus (n):", &format!("{} chars", n.len()))
        );
    }
    if let Some(ref e) = key.e {
        println!("{}", fmt.key_val("Exponent (e):", e));
    }
}
