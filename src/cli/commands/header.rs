//! Command handler for `header`.

use anyhow::Result;

use crate::cli::args::HeaderArgs;
use crate::cli::exit_codes::CliExit;
use crate::cli::formatting::Formatter;
use crate::domain::jwt::JwtToken;

/// Executes the `header` command, extracting and outputting only the parsed JOSE header.
///
/// # Arguments
///
/// * `args` - Parsed header command options.
/// * `fmt` - Terminal formatter for colors and styling.
/// * `quiet` - If `true`, suppresses stdout on success.
///
/// # Errors
///
/// Returns an error if token resolution or JSON serialization fails.
pub fn execute(args: &HeaderArgs, fmt: &Formatter, quiet: bool) -> Result<CliExit> {
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
        println!("{}", serde_json::to_string(&token.header_json)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&token.header_json)?);
    }

    Ok(CliExit::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::TokenInputArgs;
    use crate::cli::formatting::ColorChoice;

    #[test]
    fn test_header_command_execution() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.sig";
        let args = HeaderArgs {
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
