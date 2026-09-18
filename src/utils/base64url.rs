//! Base64URL encoding and decoding utilities without padding (RFC 7515 / RFC 4648).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use thiserror::Error;

/// Errors that can occur during Base64URL decoding.
#[derive(Debug, Error)]
pub enum Base64UrlError {
    /// An error occurred while decoding the Base64URL payload.
    #[error("Base64URL decoding failed: {0}")]
    DecodeError(#[from] base64::DecodeError),
}

/// Decodes an unpadded Base64URL-encoded string into raw bytes.
///
/// Trims surrounding whitespace and removes any trailing padding characters (`=`)
/// for maximum compatibility with both strict and relaxed Base64URL inputs.
///
/// # Arguments
///
/// * `input` - The Base64URL encoded string slice.
///
/// # Errors
///
/// Returns [`Base64UrlError::DecodeError`] if the input contains invalid characters
/// or is not a valid Base64URL sequence.
///
/// # Examples
///
/// ```
/// use jwt_debugger::utils::base64url::decode_base64url;
///
/// let decoded = decode_base64url("eyJhbGciOiJIUzI1NiJ9").unwrap();
/// assert_eq!(String::from_utf8(decoded).unwrap(), r#"{"alg":"HS256"}"#);
/// ```
pub fn decode_base64url(input: &str) -> Result<Vec<u8>, Base64UrlError> {
    let sanitized = input.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(sanitized).map_err(Into::into)
}

/// Encodes raw bytes into an unpadded Base64URL string according to RFC 7515.
///
/// # Arguments
///
/// * `input` - The byte slice to encode.
///
/// # Examples
///
/// ```
/// use jwt_debugger::utils::base64url::encode_base64url;
///
/// let encoded = encode_base64url(br#"{"alg":"HS256"}"#);
/// assert_eq!(encoded, "eyJhbGciOiJIUzI1NiJ9");
/// ```
pub fn encode_base64url(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_and_decode_base64url() {
        let original = b"Hello, JWT World!";
        let encoded = encode_base64url(original);
        assert_eq!(encoded, "SGVsbG8sIEpXVCBXb3JsZCE");

        let decoded = decode_base64url(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_with_padding_or_whitespace() {
        let decoded = decode_base64url("  SGVsbG8sIEpXVCBXb3JsZCE=  ").unwrap();
        assert_eq!(decoded, b"Hello, JWT World!");
    }

    #[test]
    fn test_decode_invalid_base64url() {
        assert!(decode_base64url("???invalid???").is_err());
    }
}
