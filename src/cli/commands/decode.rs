//! Command handler for `decode`.

use anyhow::Result;

use crate::application::decode::decode_jwt;
use crate::cli::args::DecodeArgs;
use crate::cli::exit_codes::CliExit;
use crate::cli::formatting::Formatter;
use crate::domain::jwt::JwtToken;

/// Executes the `decode` command, displaying JWT header, payload, and signature details.
///
/// # Arguments
///
/// * `args` - Parsed decode command options.
/// * `fmt` - Terminal formatter for colors and styling.
/// * `quiet` - If `true`, suppresses stdout on success.
///
/// # Errors
///
/// Returns an error if token resolution or JSON serialization fails.
pub fn execute(args: &DecodeArgs, fmt: &Formatter, quiet: bool) -> Result<CliExit> {
    let raw_token = args.input.resolve_token()?;
    let token = match JwtToken::parse(&raw_token) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{}: {err}", fmt.invalid("Error parsing JWT"));
            return Ok(CliExit::MalformedJwt);
        }
    };

    let report = decode_jwt(&token);

    if args.json {
        let json_str = serde_json::to_string_pretty(&report)?;
        println!("{json_str}");
        return Ok(CliExit::Success);
    }

    if !quiet {
        // Header
        println!("{}", fmt.section("Header"));
        if args.compact {
            println!("{}", serde_json::to_string(&report.header)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&report.header)?);
        }
        println!();

        // Payload
        println!("{}", fmt.section("Payload"));
        if args.compact {
            println!("{}", serde_json::to_string(&report.payload)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&report.payload)?);
        }
        println!();

        // Signature
        println!("{}", fmt.section("Signature"));
        println!("{}", fmt.key_val("Algorithm:", &report.signature.algorithm));
        println!("{}", fmt.key_val("Base64URL:", &report.signature.base64url));
        println!(
            "{}",
            fmt.key_val("Bytes:", &report.signature.bytes.to_string())
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
    fn test_decode_command_execution() {
        let raw = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig";
        let args = DecodeArgs {
            input: TokenInputArgs {
                token_arg: Some(raw.to_string()),
                ..Default::default()
            },
            pretty: false,
            compact: false,
            json: true,
        };
        let fmt = Formatter::new(ColorChoice::Never);
        let res = execute(&args, &fmt, false).unwrap();
        assert_eq!(res, CliExit::Success);
    }
}
