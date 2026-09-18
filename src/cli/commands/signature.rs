//! Command handler for `signature`.

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::io::{self, Write};

use crate::application::decode::decode_signature_only;
use crate::cli::args::SignatureArgs;
use crate::cli::exit_codes::CliExit;
use crate::cli::formatting::Formatter;
use crate::domain::jwt::JwtToken;

/// Executes the `signature` command, extracting and formatting the signature in requested encodings.
///
/// # Arguments
///
/// * `args` - Parsed signature command options.
/// * `fmt` - Terminal formatter for colors and styling.
/// * `quiet` - If `true`, suppresses stdout on success.
///
/// # Errors
///
/// Returns an error if token resolution, I/O writing, or JSON serialization fails.
pub fn execute(args: &SignatureArgs, fmt: &Formatter, quiet: bool) -> Result<CliExit> {
    let raw_token = args.input.resolve_token()?;
    let token = match JwtToken::parse(&raw_token) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{}: {err}", fmt.invalid("Error parsing JWT"));
            return Ok(CliExit::MalformedJwt);
        }
    };

    if args.raw {
        io::stdout().write_all(&token.signature_bytes)?;
        io::stdout().flush()?;
        return Ok(CliExit::Success);
    }

    if args.hex {
        println!("{}", hex::encode(&token.signature_bytes));
        return Ok(CliExit::Success);
    }

    if args.base64 {
        println!("{}", STANDARD.encode(&token.signature_bytes));
        return Ok(CliExit::Success);
    }

    if args.base64url {
        println!("{}", token.encoded_signature);
        return Ok(CliExit::Success);
    }

    let report = decode_signature_only(&token);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(CliExit::Success);
    }

    if !quiet {
        println!("{}", fmt.section("JWT Signature"));
        println!("{}", fmt.key_val("Algorithm:", &report.algorithm));
        println!("{}", fmt.key_val("Base64URL:", &report.base64url));
        println!("{}", fmt.key_val("Hex:", &report.hex));
        println!(
            "{}",
            fmt.key_val("Length:", &format!("{} bytes", report.bytes))
        );
    }

    Ok(CliExit::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::TokenInputArgs;
    use crate::cli::formatting::ColorChoice;

    #[test]
    fn test_signature_command_execution_hex() {
        let raw = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln";
        let args = SignatureArgs {
            input: TokenInputArgs {
                token_arg: Some(raw.to_string()),
                ..Default::default()
            },
            raw: false,
            hex: true,
            base64: false,
            base64url: false,
            json: false,
        };
        let fmt = Formatter::new(ColorChoice::Never);
        let res = execute(&args, &fmt, false).unwrap();
        assert_eq!(res, CliExit::Success);
    }
}
