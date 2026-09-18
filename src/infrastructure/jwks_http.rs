//! Secure remote JWKS retrieval over HTTP/HTTPS with redirect protection and payload size bounding.

use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use std::io::Read;
use std::time::Duration;
use url::Url;

use crate::domain::error::JwksError;
use crate::domain::jwk::Jwks;
use crate::domain::jwt::MAX_JWKS_SIZE;
use crate::jwk::parser::parse_jwks;

/// Configuration options for fetching a remote JWKS.
pub struct JwksFetchOptions {
    /// Total request timeout duration.
    pub timeout: Duration,
    /// If `true`, allow insecure `http://` URLs. Default is `false` (HTTPS required).
    pub allow_insecure_http: bool,
}

impl Default for JwksFetchOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            allow_insecure_http: false,
        }
    }
}

/// Fetches a JSON Web Key Set (JWKS) from a remote URL securely.
///
/// # Security Invariants
///
/// 1. **Zero Data Leakage**: This function ONLY executes an HTTP GET request to fetch
///    the public key set. It **NEVER** sends the user's JWT, token payload, or secret keys.
/// 2. **HTTPS Enforcement**: Rejects insecure `http://` URLs by default unless
///    explicitly allowed via [`JwksFetchOptions::allow_insecure_http`].
/// 3. **Downgrade Protection**: Rejects redirects from HTTPS to plain HTTP.
/// 4. **Resource Bounding**: Limits response size to [`MAX_JWKS_SIZE`] (1 MB) to prevent denial-of-service.
///
/// # Arguments
///
/// * `url_str` - The remote JWKS endpoint URL (e.g. `https://example.com/.well-known/jwks.json`).
/// * `options` - Fetch options including timeout and HTTP security policy.
///
/// # Errors
///
/// Returns [`JwksError`] if the URL is invalid, scheme is insecure, request times out,
/// status code is non-2xx, response is too large, or JSON parsing fails.
///
/// # Examples
///
/// ```no_run
/// use jwt_debugger::infrastructure::{JwksFetchOptions, fetch_remote_jwks};
///
/// let options = JwksFetchOptions::default();
/// let jwks = fetch_remote_jwks("https://auth.example.com/.well-known/jwks.json", &options);
/// ```
pub fn fetch_remote_jwks(url_str: &str, options: &JwksFetchOptions) -> Result<Jwks, JwksError> {
    let url = Url::parse(url_str)
        .map_err(|e| JwksError::Network(format!("Invalid URL '{url_str}': {e}")))?;

    // Enforce HTTPS
    if url.scheme() == "http" && !options.allow_insecure_http {
        return Err(JwksError::InsecureHttpNotAllowed(url_str.to_string()));
    } else if url.scheme() != "https" && url.scheme() != "http" {
        return Err(JwksError::Network(format!(
            "Unsupported URL scheme '{}'. Must be https:// (or http:// with --allow-insecure-http)",
            url.scheme()
        )));
    }

    // Build HTTP client with security boundaries
    let client = Client::builder()
        .timeout(options.timeout)
        .connect_timeout(Duration::from_secs(3))
        .redirect(Policy::custom(|attempt| {
            if attempt.previous().len() >= 3 {
                attempt.error("Too many redirects")
            } else if attempt.url().scheme() == "http" && attempt.previous()[0].scheme() == "https"
            {
                attempt.error("Cannot redirect from HTTPS to insecure HTTP")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|e| JwksError::Network(format!("Failed to build HTTP client: {e}")))?;

    let mut response = client
        .get(url)
        .header(
            reqwest::header::ACCEPT,
            "application/json, application/jwk-set+json",
        )
        .send()
        .map_err(|e| {
            if e.is_timeout() {
                JwksError::Timeout(format!("{:?}", options.timeout))
            } else {
                JwksError::Network(e.to_string())
            }
        })?;

    if !response.status().is_success() {
        return Err(JwksError::HttpStatus(response.status().as_u16()));
    }

    // Read response with bounded size
    let mut buffer = Vec::new();
    let mut reader = (&mut response).take(MAX_JWKS_SIZE as u64 + 1);
    reader
        .read_to_end(&mut buffer)
        .map_err(|e| JwksError::Network(format!("Failed to read JWKS response body: {e}")))?;

    if buffer.len() > MAX_JWKS_SIZE {
        return Err(JwksError::ResponseTooLarge(MAX_JWKS_SIZE));
    }

    let json_str = std::str::from_utf8(&buffer)
        .map_err(|e| JwksError::InvalidJson(format!("JWKS response is not valid UTF-8: {e}")))?;

    parse_jwks(json_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_rejects_insecure_http_by_default() {
        let options = JwksFetchOptions {
            allow_insecure_http: false,
            timeout: Duration::from_secs(1),
        };

        let err = fetch_remote_jwks("http://example.com/jwks.json", &options).unwrap_err();
        assert!(matches!(err, JwksError::InsecureHttpNotAllowed(_)));
    }

    #[test]
    fn test_fetch_rejects_unsupported_scheme() {
        let options = JwksFetchOptions::default();
        let err = fetch_remote_jwks("ftp://example.com/jwks.json", &options).unwrap_err();
        assert!(matches!(err, JwksError::Network(_)));
    }
}
