//! Infrastructure layer providing filesystem access, stdin reading, and secure remote JWKS fetching over HTTP/HTTPS.

pub mod filesystem;
pub mod jwks_http;
pub mod stdin;

pub use filesystem::{MAX_FILE_SIZE, read_file_to_bytes, read_file_to_string};
pub use jwks_http::{JwksFetchOptions, fetch_remote_jwks};
pub use stdin::{is_stdin_terminal, read_stdin};
