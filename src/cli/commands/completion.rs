//! Command handler for `completion`.

use anyhow::Result;
use clap::CommandFactory;
use clap_complete::generate;
use std::io;

use crate::cli::args::{Cli, CompletionArgs};
use crate::cli::exit_codes::CliExit;

/// Executes the `completion` command, generating shell autocomplete scripts.
///
/// # Arguments
///
/// * `args` - Parsed shell completion arguments specifying the target shell.
///
/// # Errors
///
/// Returns an error if generating or writing completion to stdout fails.
pub fn execute(args: &CompletionArgs) -> Result<CliExit> {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    generate(args.shell, &mut cmd, bin_name, &mut io::stdout());
    Ok(CliExit::Success)
}
