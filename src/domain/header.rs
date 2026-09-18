//! JOSE Header representation as defined in RFC 7515 Section 4.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

use super::algorithm::JwtAlgorithm;
use super::error::JwtError;

/// JOSE (JSON Object Signing and Encryption) Header for JWS tokens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwtHeader {
    /// Algorithm (`alg`) header parameter identifying the cryptographic algorithm used.
    pub alg: String,

    /// Type (`typ`) header parameter declaring the media type of the complete JWS (e.g. `"JWT"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Content Type (`cty`) header parameter declaring the media type of the secured content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,

    /// Key ID (`kid`) header parameter indicating which key was used to secure the JWS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// JWK Set URL (`jku`) header parameter referring to a resource for a set of JSON-encoded public keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,

    /// JSON Web Key (`jwk`) header parameter containing the public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<serde_json::Value>,

    /// X.509 URL (`x5u`) header parameter referring to a resource for the X.509 certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// X.509 Certificate Chain (`x5c`) header parameter containing certificate data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    /// X.509 Certificate SHA-1 Thumbprint (`x5t`) header parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    /// Critical (`crit`) header parameter listing extensions that MUST be understood.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,

    /// Additional custom/unregistered header parameters.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl JwtHeader {
    /// Parses the `alg` header string into a strongly-typed [`JwtAlgorithm`].
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::UnsupportedAlgorithm`] if the algorithm is unrecognized.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::domain::{JwtAlgorithm, JwtHeader};
    ///
    /// let header = JwtHeader {
    ///     alg: "RS256".to_string(),
    ///     typ: Some("JWT".to_string()),
    ///     cty: None,
    ///     kid: Some("key-1".to_string()),
    ///     jku: None,
    ///     jwk: None,
    ///     x5u: None,
    ///     x5c: None,
    ///     x5t: None,
    ///     crit: None,
    ///     extra: serde_json::Map::new(),
    /// };
    ///
    /// assert_eq!(header.parse_algorithm().unwrap(), JwtAlgorithm::RS256);
    /// ```
    pub fn parse_algorithm(&self) -> Result<JwtAlgorithm, JwtError> {
        JwtAlgorithm::from_str(&self.alg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_header_deserialization() {
        let val = json!({
            "alg": "HS256",
            "typ": "JWT",
            "kid": "my-key-id",
            "custom_header": 123
        });

        let header: JwtHeader = serde_json::from_value(val).unwrap();
        assert_eq!(header.alg, "HS256");
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        assert_eq!(header.kid.as_deref(), Some("my-key-id"));
        assert_eq!(header.parse_algorithm().unwrap(), JwtAlgorithm::HS256);
        assert_eq!(header.extra.get("custom_header"), Some(&json!(123)));
    }
}
