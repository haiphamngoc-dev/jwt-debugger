//! Command handler for `payload`.

use anyhow::Result;

use crate::cli::args::PayloadArgs;
use crate::cli::exit_codes::CliExit;
use crate::cli::formatting::Formatter;
use crate::domain::jwt::JwtToken;

/// Executes the `payload` command, extracting and outputting only the parsed payload claims.
///
/// # Arguments
///
/// * `args` - Parsed payload command options.
/// * `fmt` - Terminal formatter for colors and styling.
/// * `quiet` - If `true`, suppresses stdout on success.
///
/// # Errors
///
/// Returns an error if token resolution or JSON serialization fails.
pub fn execute(args: &PayloadArgs, fmt: &Formatter, quiet: bool) -> Result<CliExit> {
    let raw_token = args.input.resolve_token()?;
    let token = match JwtToken::parse(&raw_token) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{}: {err}", fmt.invalid("Error parsing JWT"));
            return Ok(CliExit::MalformedJwt);
        }
    };

    if quiet {
        return Ok(CliExit::Success);
    }

    if args.compact {
        println!("{}", serde_json::to_string(&token.payload_json)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&token.payload_json)?);
    }

    Ok(CliExit::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::TokenInputArgs;
    use crate::cli::formatting::ColorChoice;

    #[test]
    fn test_payload_command_execution() {
        let raw = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig";
        let args = PayloadArgs {
            input: TokenInputArgs {
                token_arg: Some(raw.to_string()),
                ..Default::default()
            },
            pretty: true,
            compact: false,
            json: false,
        };
        let fmt = Formatter::new(ColorChoice::Never);
        let res = execute(&args, &fmt, false).unwrap();
        assert_eq!(res, CliExit::Success);
    }
}
