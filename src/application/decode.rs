//! Token decoding and formatting into structured JSON reports.

use serde::{Deserialize, Serialize};

use crate::domain::jwt::JwtToken;

/// Complete decoded report of a JWT including header, payload, signature, and byte metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedJwtReport {
    /// Parsed JSON header.
    pub header: serde_json::Value,
    /// Parsed JSON payload.
    pub payload: serde_json::Value,
    /// Decoded signature metadata.
    pub signature: DecodedSignatureReport,
    /// Token structural metadata.
    pub metadata: DecodeMetadata,
}

/// Decoded signature details including algorithm name, Base64URL string, hex string, and byte length.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedSignatureReport {
    /// Algorithm specified in the header.
    pub algorithm: String,
    /// Base64URL encoded signature string.
    pub base64url: String,
    /// Hexadecimal encoded signature string.
    pub hex: String,
    /// Signature length in bytes.
    pub bytes: usize,
}

/// Metadata describing token segments and byte lengths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeMetadata {
    /// Number of dot-separated segments (always 3 for JWS).
    pub segments: usize,
    /// Total length of raw token string in bytes.
    pub raw_bytes: usize,
    /// Length of the ASCII signing input (`header.payload`) in bytes.
    pub signing_input_bytes: usize,
}

/// Decodes a [`JwtToken`] into a full [`DecodedJwtReport`].
///
/// # Arguments
///
/// * `token` - The parsed JWT token.
///
/// # Examples
///
/// ```
/// use jwt_debugger::application::decode_jwt;
/// use jwt_debugger::domain::JwtToken;
///
/// let token = JwtToken::parse("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig").unwrap();
/// let report = decode_jwt(&token);
/// assert_eq!(report.signature.algorithm, "HS256");
/// assert_eq!(report.metadata.segments, 3);
/// ```
pub fn decode_jwt(token: &JwtToken) -> DecodedJwtReport {
    let hex_sig = hex::encode(&token.signature_bytes);

    DecodedJwtReport {
        header: token.header_json.clone(),
        payload: token.payload_json.clone(),
        signature: DecodedSignatureReport {
            algorithm: token.header.alg.clone(),
            base64url: token.encoded_signature.clone(),
            hex: hex_sig,
            bytes: token.signature_bytes.len(),
        },
        metadata: DecodeMetadata {
            segments: 3,
            raw_bytes: token.raw.len(),
            signing_input_bytes: token.signing_input_bytes().len(),
        },
    }
}

/// Extracts only signature details from a [`JwtToken`] into a [`DecodedSignatureReport`].
///
/// # Arguments
///
/// * `token` - The parsed JWT token.
///
/// # Examples
///
/// ```
/// use jwt_debugger::application::decode_signature_only;
/// use jwt_debugger::domain::JwtToken;
///
/// let token = JwtToken::parse("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln").unwrap();
/// let sig = decode_signature_only(&token);
/// assert_eq!(sig.algorithm, "HS256");
/// assert_eq!(sig.base64url, "c2ln");
/// ```
pub fn decode_signature_only(token: &JwtToken) -> DecodedSignatureReport {
    DecodedSignatureReport {
        algorithm: token.header.alg.clone(),
        base64url: token.encoded_signature.clone(),
        hex: hex::encode(&token.signature_bytes),
        bytes: token.signature_bytes.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_jwt() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2ln";
        let token = JwtToken::parse(raw).unwrap();
        let report = decode_jwt(&token);

        assert_eq!(report.header["alg"], "HS256");
        assert_eq!(report.payload["sub"], "1234567890");
        assert_eq!(report.signature.algorithm, "HS256");
        assert_eq!(report.metadata.segments, 3);
        assert_eq!(report.metadata.raw_bytes, raw.len());
    }
}
