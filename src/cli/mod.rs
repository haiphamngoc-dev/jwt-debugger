//! Command-line interface (CLI) module for `jwt-debugger`.
//!
//! Provides command routing, argument parsing with `clap`, terminal formatting,
//! exit code management, and execution of all subcommands (`decode`, `inspect`,
//! `verify`, `claims`, `header`, `payload`, `signature`, `jwk`, `completion`).

pub mod args;
pub mod commands;
pub mod exit_codes;
pub mod formatting;

use clap::Parser;
use std::process::ExitCode;

use self::args::{Cli, Commands};
use self::formatting::Formatter;

/// Main entry point for the CLI application.
///
/// Parses command-line arguments, configures terminal color formatting,
/// dispatches execution to the corresponding subcommand handler, and maps the
/// result to a process [`ExitCode`].
///
/// # Returns
///
/// Returns standard [`ExitCode`] indicating success (`0`) or specific error categories.
pub fn run() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(err) => {
            // Let clap format usage errors or --help / --version
            let _ = err.print();
            return if err.use_stderr() {
                ExitCode::from(exit_codes::EXIT_INVALID_USAGE)
            } else {
                ExitCode::from(exit_codes::EXIT_SUCCESS)
            };
        }
    };

    let fmt = Formatter::new(cli.color);
    let quiet = cli.quiet;

    let result = match &cli.command {
        Commands::Decode(args) => commands::decode::execute(args, &fmt, quiet),
        Commands::Inspect(args) => commands::inspect::execute(args, &fmt, quiet),
        Commands::Verify(args) => commands::verify::execute(args, &fmt, quiet),
        Commands::Claims(args) => commands::claims::execute(args, &fmt, quiet),
        Commands::Header(args) => commands::header::execute(args, &fmt, quiet),
        Commands::Payload(args) => commands::payload::execute(args, &fmt, quiet),
        Commands::Signature(args) => commands::signature::execute(args, &fmt, quiet),
        Commands::Jwk(args) => commands::jwk::execute(args, &fmt, quiet),
        Commands::Completion(args) => commands::completion::execute(args),
    };

    match result {
        Ok(exit) => exit.to_exit_code(),
        Err(err) => {
            eprintln!("{}: {err:#}", fmt.invalid("Error"));
            ExitCode::from(exit_codes::EXIT_GENERIC_ERROR)
        }
    }
}
