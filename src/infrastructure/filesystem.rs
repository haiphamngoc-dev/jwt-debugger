//! Safe filesystem access with bounded file sizes and contextual error handling.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};

/// Maximum allowed file size for reading into memory (10 MB) to prevent denial-of-service.
pub const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Reads a UTF-8 text file from disk into a [`String`], enforcing a maximum file size limit of 10 MB.
///
/// # Arguments
///
/// * `path` - Path to the file to read.
///
/// # Errors
///
/// Returns an error if the file cannot be opened, exceeds [`MAX_FILE_SIZE`],
/// cannot be read, or is not valid UTF-8.
///
/// # Examples
///
/// ```no_run
/// use jwt_debugger::infrastructure::read_file_to_string;
///
/// let content = read_file_to_string("Cargo.toml").unwrap();
/// assert!(content.contains("[package]"));
/// ```
pub fn read_file_to_string<P: AsRef<Path>>(path: P) -> Result<String> {
    let p = path.as_ref();
    let mut file =
        File::open(p).with_context(|| format!("Failed to open file '{}'", p.display()))?;

    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to read metadata for '{}'", p.display()))?;

    if metadata.len() > MAX_FILE_SIZE as u64 {
        anyhow::bail!(
            "File '{}' exceeds maximum allowed size of {} bytes",
            p.display(),
            MAX_FILE_SIZE
        );
    }

    let mut content = String::new();
    file.read_to_string(&mut content)
        .with_context(|| format!("Failed to read content from '{}'", p.display()))?;

    Ok(content)
}

/// Reads raw bytes from a file on disk, enforcing a maximum file size limit of 10 MB.
///
/// # Arguments
///
/// * `path` - Path to the file to read.
///
/// # Errors
///
/// Returns an error if the file cannot be opened, exceeds [`MAX_FILE_SIZE`],
/// or cannot be read.
///
/// # Examples
///
/// ```no_run
/// use jwt_debugger::infrastructure::read_file_to_bytes;
///
/// let bytes = read_file_to_bytes("Cargo.toml").unwrap();
/// assert!(!bytes.is_empty());
/// ```
pub fn read_file_to_bytes<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let p = path.as_ref();
    let mut file =
        File::open(p).with_context(|| format!("Failed to open file '{}'", p.display()))?;

    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to read metadata for '{}'", p.display()))?;

    if metadata.len() > MAX_FILE_SIZE as u64 {
        anyhow::bail!(
            "File '{}' exceeds maximum allowed size of {} bytes",
            p.display(),
            MAX_FILE_SIZE
        );
    }

    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .with_context(|| format!("Failed to read bytes from '{}'", p.display()))?;

    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_existing_file() {
        let content = read_file_to_string("Cargo.toml").unwrap();
        assert!(content.contains("jwt-debugger"));

        let bytes = read_file_to_bytes("Cargo.toml").unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_read_non_existent_file() {
        assert!(read_file_to_string("non_existent_file_12345.xyz").is_err());
        assert!(read_file_to_bytes("non_existent_file_12345.xyz").is_err());
    }
}
