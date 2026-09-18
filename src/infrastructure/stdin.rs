//! Standard input (stdin) reading with token size limits and terminal interactivity detection.

use anyhow::{Context, Result, bail};
use std::io::{self, IsTerminal, Read};

use crate::domain::jwt::MAX_TOKEN_SIZE;

/// Reads input from standard input up to [`MAX_TOKEN_SIZE`] (128 KB).
///
/// Trims surrounding whitespace and validates that the content is non-empty and valid UTF-8.
///
/// # Errors
///
/// Returns an error if reading fails, content exceeds [`MAX_TOKEN_SIZE`],
/// content is not valid UTF-8, or trimmed input is empty.
///
/// # Examples
///
/// ```no_run
/// use jwt_debugger::infrastructure::read_stdin;
///
/// // Reads piped input: echo -n "eyJ..." | jwt-debugger inspect
/// let token = read_stdin().unwrap();
/// ```
pub fn read_stdin() -> Result<String> {
    let mut stdin = io::stdin();
    let mut buffer = Vec::new();

    // Read with size limit to prevent memory abuse
    let mut handle = (&mut stdin).take(MAX_TOKEN_SIZE as u64 + 1);
    handle
        .read_to_end(&mut buffer)
        .context("Failed to read from standard input")?;

    if buffer.len() > MAX_TOKEN_SIZE {
        bail!("Standard input exceeds maximum allowed token size of {MAX_TOKEN_SIZE} bytes");
    }

    let s = String::from_utf8(buffer).context("Standard input is not valid UTF-8")?;
    let trimmed = s.trim();

    if trimmed.is_empty() {
        bail!("Standard input is empty");
    }

    Ok(trimmed.to_string())
}

/// Checks if standard input is attached to an interactive terminal (TTY) versus a pipe or file redirection.
///
/// # Examples
///
/// ```
/// use jwt_debugger::infrastructure::is_stdin_terminal;
///
/// let is_terminal = is_stdin_terminal();
/// ```
pub fn is_stdin_terminal() -> bool {
    io::stdin().is_terminal()
}
