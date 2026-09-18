//! Terminal color formatting and styled output helper.

use colored::Colorize;
use std::io::{self, IsTerminal};

/// Terminal color output preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum ColorChoice {
    /// Enable colors automatically if stdout is an interactive terminal.
    #[default]
    Auto,
    /// Always enable ANSI colors.
    Always,
    /// Never use ANSI color codes.
    Never,
}

/// Helper for rendering styled, colorized terminal text and key-value sections.
pub struct Formatter {
    color_enabled: bool,
}

impl Formatter {
    /// Creates a new [`Formatter`] based on the chosen [`ColorChoice`].
    pub fn new(choice: ColorChoice) -> Self {
        let color_enabled = match choice {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => io::stdout().is_terminal(),
        };

        if !color_enabled {
            colored::control::set_override(false);
        } else if choice == ColorChoice::Always {
            colored::control::set_override(true);
        }

        Self { color_enabled }
    }

    /// Formats a primary title in bold cyan.
    pub fn title(&self, text: &str) -> String {
        if self.color_enabled {
            text.bold().cyan().to_string()
        } else {
            text.to_string()
        }
    }

    /// Formats a section header with an underline.
    pub fn section(&self, text: &str) -> String {
        if self.color_enabled {
            format!("{}\n{}", text.bold().underline(), "─".repeat(text.len()))
        } else {
            format!("{}\n{}", text, "-".repeat(text.len()))
        }
    }

    /// Formats a key-value pair aligned in a 15-character column.
    pub fn key_val(&self, key: &str, val: &str) -> String {
        if self.color_enabled {
            format!("{:<15} {}", key.dimmed(), val.bold())
        } else {
            format!("{:<15} {}", key, val)
        }
    }

    /// Formats text in bold green (e.g. valid status).
    pub fn valid(&self, text: &str) -> String {
        if self.color_enabled {
            text.green().bold().to_string()
        } else {
            text.to_string()
        }
    }

    /// Formats text in bold red (e.g. invalid status or error).
    pub fn invalid(&self, text: &str) -> String {
        if self.color_enabled {
            text.red().bold().to_string()
        } else {
            text.to_string()
        }
    }

    /// Formats text in bold yellow (e.g. security warning).
    pub fn warning(&self, text: &str) -> String {
        if self.color_enabled {
            text.yellow().bold().to_string()
        } else {
            text.to_string()
        }
    }

    /// Formats text in dimmed/muted style.
    pub fn muted(&self, text: &str) -> String {
        if self.color_enabled {
            text.dimmed().to_string()
        } else {
            text.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_formatter_never_color() {
        let fmt = Formatter::new(ColorChoice::Never);
        assert_eq!(fmt.valid("OK"), "OK");
        assert_eq!(fmt.invalid("FAIL"), "FAIL");
        assert_eq!(fmt.title("TITLE"), "TITLE");
    }
}
