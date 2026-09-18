//! JSON parsing utilities for JWK and JWKS structures.

use crate::domain::error::JwksError;
use crate::domain::jwk::{JwkKey, Jwks};

/// Parses a JSON Web Key (JWK) JSON string into a [`JwkKey`].
///
/// # Arguments
///
/// * `json_str` - The raw JSON string of the JWK.
///
/// # Errors
///
/// Returns [`JwksError::InvalidJson`] if the input string cannot be deserialized.
///
/// # Examples
///
/// ```
/// use jwt_debugger::jwk::parse_jwk;
///
/// let json = r#"{
///     "kty": "RSA",
///     "use": "sig",
///     "kid": "key-1",
///     "n": "u1SU...",
///     "e": "AQAB"
/// }"#;
///
/// let jwk = parse_jwk(json).unwrap();
/// assert_eq!(jwk.kty, "RSA");
/// assert_eq!(jwk.kid.as_deref(), Some("key-1"));
/// ```
pub fn parse_jwk(json_str: &str) -> Result<JwkKey, JwksError> {
    serde_json::from_str(json_str.trim())
        .map_err(|e| JwksError::InvalidJson(format!("Invalid JWK JSON: {e}")))
}

/// Parses a JSON Web Key Set (JWKS) JSON string into a [`Jwks`].
///
/// # Arguments
///
/// * `json_str` - The raw JSON string representing the JWK Set object `{"keys": [...]}`.
///
/// # Errors
///
/// Returns [`JwksError::InvalidJson`] if the input string cannot be deserialized.
///
/// # Examples
///
/// ```
/// use jwt_debugger::jwk::parse_jwks;
///
/// let json = r#"{
///     "keys": [
///         { "kty": "RSA", "kid": "key-1" },
///         { "kty": "EC", "kid": "key-2", "crv": "P-256" }
///     ]
/// }"#;
///
/// let jwks = parse_jwks(json).unwrap();
/// assert_eq!(jwks.keys.len(), 2);
/// ```
pub fn parse_jwks(json_str: &str) -> Result<Jwks, JwksError> {
    serde_json::from_str(json_str.trim())
        .map_err(|e| JwksError::InvalidJson(format!("Invalid JWKS JSON: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jwk_valid_and_invalid() {
        let valid = r#"{"kty":"oct","k":"c2VjcmV0"}"#;
        let key = parse_jwk(valid).unwrap();
        assert_eq!(key.kty, "oct");
        assert_eq!(key.k.as_deref(), Some("c2VjcmV0"));

        let invalid = "not valid json";
        assert!(parse_jwk(invalid).is_err());
    }

    #[test]
    fn test_parse_jwks_valid_and_invalid() {
        let valid = r#"{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}"#;
        let jwks = parse_jwks(valid).unwrap();
        assert_eq!(jwks.keys.len(), 1);

        let invalid = r#"{"keys": "not an array"}"#;
        assert!(parse_jwks(invalid).is_err());
    }
}
