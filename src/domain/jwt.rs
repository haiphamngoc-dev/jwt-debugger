//! Core JWT (JSON Web Token) model, segment parsing, and token size limits.

use crate::utils::base64url::decode_base64url;

use super::claims::StandardClaims;
use super::error::JwtError;
use super::header::JwtHeader;

/// Maximum allowed total JWT string length in bytes (128 KB).
pub const MAX_TOKEN_SIZE: usize = 128 * 1024; // 128 KB

/// Maximum allowed decoded JOSE header size in bytes (32 KB).
pub const MAX_HEADER_SIZE: usize = 32 * 1024; // 32 KB

/// Maximum allowed decoded payload size in bytes (128 KB).
pub const MAX_PAYLOAD_SIZE: usize = 128 * 1024; // 128 KB

/// Maximum allowed JWKS response size in bytes (1 MB).
pub const MAX_JWKS_SIZE: usize = 1024 * 1024; // 1 MB

/// Parsed representation of a signed JSON Web Token (JWS / Compact Serialization).
#[derive(Debug, Clone)]
pub struct JwtToken {
    /// The trimmed raw input JWT string.
    pub raw: String,
    /// Base64URL-encoded header segment.
    pub encoded_header: String,
    /// Base64URL-encoded payload segment.
    pub encoded_payload: String,
    /// Base64URL-encoded signature segment.
    pub encoded_signature: String,

    /// Decoded raw bytes of the JOSE header.
    pub header_bytes: Vec<u8>,
    /// Decoded raw bytes of the payload.
    pub payload_bytes: Vec<u8>,
    /// Decoded raw bytes of the signature.
    pub signature_bytes: Vec<u8>,

    /// Parsed JSON object of the JOSE header.
    pub header_json: serde_json::Value,
    /// Parsed JSON object of the payload.
    pub payload_json: serde_json::Value,

    /// Structured header model.
    pub header: JwtHeader,
    /// Structured registered and custom claims model.
    pub claims: StandardClaims,
}

impl JwtToken {
    /// Parses and validates the format, segment count, Base64URL encoding, and JSON structure of a compact JWT string.
    ///
    /// # Arguments
    ///
    /// * `raw_token` - The compact dot-separated JWT string.
    ///
    /// # Errors
    ///
    /// Returns [`JwtError`] if the token is empty, too large, is a 5-segment JWE,
    /// contains an invalid number of segments, or has invalid Base64URL/JSON/UTF-8.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::domain::JwtToken;
    ///
    /// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozsmw6Mo_Edk_mI_m_8eH_p_Huu_w5z_oYqGgqMvvg";
    /// let jwt = JwtToken::parse(token).expect("valid token");
    /// assert_eq!(jwt.header.alg, "HS256");
    /// assert_eq!(jwt.claims.sub.as_deref(), Some("1234567890"));
    /// ```
    pub fn parse(raw_token: &str) -> Result<Self, JwtError> {
        let trimmed = raw_token.trim();
        if trimmed.is_empty() {
            return Err(JwtError::EmptyToken);
        }

        if trimmed.len() > MAX_TOKEN_SIZE {
            return Err(JwtError::TokenTooLarge(trimmed.len()));
        }

        let segments: Vec<&str> = trimmed.split('.').collect();
        if segments.len() == 5 {
            return Err(JwtError::JweNotSupported);
        }
        if segments.len() != 3 {
            return Err(JwtError::InvalidSegmentCount(segments.len()));
        }

        let encoded_header = segments[0];
        let encoded_payload = segments[1];
        let encoded_signature = segments[2];

        // 1. Decode Header
        let header_bytes = decode_base64url(encoded_header)
            .map_err(|e| JwtError::InvalidHeaderEncoding(e.to_string()))?;

        if header_bytes.len() > MAX_HEADER_SIZE {
            return Err(JwtError::TokenTooLarge(header_bytes.len()));
        }

        let header_str = std::str::from_utf8(&header_bytes)
            .map_err(|e| JwtError::InvalidHeaderUtf8(e.to_string()))?;

        let header_json: serde_json::Value = serde_json::from_str(header_str)
            .map_err(|e| JwtError::InvalidHeaderJson(e.to_string()))?;

        let header: JwtHeader = serde_json::from_value(header_json.clone())
            .map_err(|e| JwtError::InvalidHeaderJson(e.to_string()))?;

        // 2. Decode Payload
        let payload_bytes = decode_base64url(encoded_payload)
            .map_err(|e| JwtError::InvalidPayloadEncoding(e.to_string()))?;

        if payload_bytes.len() > MAX_PAYLOAD_SIZE {
            return Err(JwtError::TokenTooLarge(payload_bytes.len()));
        }

        let payload_str = std::str::from_utf8(&payload_bytes)
            .map_err(|e| JwtError::InvalidPayloadUtf8(e.to_string()))?;

        let payload_json: serde_json::Value = serde_json::from_str(payload_str)
            .map_err(|e| JwtError::InvalidPayloadJson(e.to_string()))?;

        let claims = StandardClaims::from_json_value(&payload_json);

        // 3. Decode Signature
        let signature_bytes = if encoded_signature.is_empty() {
            Vec::new()
        } else {
            decode_base64url(encoded_signature)
                .map_err(|e| JwtError::InvalidSignatureEncoding(e.to_string()))?
        };

        Ok(Self {
            raw: trimmed.to_string(),
            encoded_header: encoded_header.to_string(),
            encoded_payload: encoded_payload.to_string(),
            encoded_signature: encoded_signature.to_string(),
            header_bytes,
            payload_bytes,
            signature_bytes,
            header_json,
            payload_json,
            header,
            claims,
        })
    }

    /// Returns the exact ASCII signing input: `BASE64URL(header) + "." + BASE64URL(payload)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::domain::JwtToken;
    ///
    /// let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig";
    /// let jwt = JwtToken::parse(token).unwrap();
    /// assert_eq!(jwt.signing_input(), "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ");
    /// ```
    pub fn signing_input(&self) -> String {
        format!("{}.{}", self.encoded_header, self.encoded_payload)
    }

    /// Returns the signing input as a byte slice borrowed directly from the raw token string.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::domain::JwtToken;
    ///
    /// let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig";
    /// let jwt = JwtToken::parse(token).unwrap();
    /// assert_eq!(jwt.signing_input_bytes(), b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ");
    /// ```
    pub fn signing_input_bytes(&self) -> &[u8] {
        // Signing input is ASCII substring of raw token: [0 .. header_len + 1 + payload_len]
        let end_idx = self.encoded_header.len() + 1 + self.encoded_payload.len();
        &self.raw.as_bytes()[..end_idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_jwt() {
        // {"alg":"HS256","typ":"JWT"}.{"sub":"1234567890","name":"John Doe","iat":1516239022}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let jwt = JwtToken::parse(token).expect("should parse valid jwt");

        assert_eq!(jwt.header.alg, "HS256");
        assert_eq!(jwt.header.typ.as_deref(), Some("JWT"));
        assert_eq!(jwt.claims.sub.as_deref(), Some("1234567890"));
        assert_eq!(jwt.claims.iat, Some(1516239022));
        assert_eq!(
            jwt.signing_input(),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        );
    }

    #[test]
    fn test_parse_jwe_rejection() {
        let jwe = "a.b.c.d.e";
        let err = JwtToken::parse(jwe).unwrap_err();
        assert_eq!(err, JwtError::JweNotSupported);
    }

    #[test]
    fn test_parse_invalid_segments() {
        assert_eq!(
            JwtToken::parse("only.two").unwrap_err(),
            JwtError::InvalidSegmentCount(2)
        );
        assert_eq!(
            JwtToken::parse("one.two.three.four").unwrap_err(),
            JwtError::InvalidSegmentCount(4)
        );
    }

    #[test]
    fn test_empty_token() {
        assert_eq!(JwtToken::parse("").unwrap_err(), JwtError::EmptyToken);
    }
}
