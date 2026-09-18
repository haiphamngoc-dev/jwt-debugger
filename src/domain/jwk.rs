//! JSON Web Key (JWK) and JWK Set (JWKS) models as defined in RFC 7517.

use serde::{Deserialize, Serialize};

/// Represents a JSON Web Key (JWK) containing public or symmetric key parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwkKey {
    /// Key type parameter (`kty`, e.g. `"RSA"`, `"EC"`, `"OKP"`, `"oct"`).
    pub kty: String,

    /// Public key use parameter (`use`, e.g. `"sig"`, `"enc"`).
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,

    /// Key operations parameter (`key_ops`, e.g. `["sign", "verify"]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,

    /// Algorithm parameter (`alg`, e.g. `"RS256"`, `"EdDSA"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// Key ID parameter (`kid`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    // RSA specific fields
    /// RSA modulus (`n`, Base64URL-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,

    /// RSA public exponent (`e`, Base64URL-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    // EC / OKP specific fields
    /// Elliptic curve name (`crv`, e.g. `"P-256"`, `"Ed25519"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,

    /// X coordinate or public key point (`x`, Base64URL-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,

    /// Y coordinate (`y`, Base64URL-encoded, for Weierstrass curves).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    // Symmetric key specific field (oct)
    /// Key value (`k`, Base64URL-encoded, for symmetric `oct` keys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,

    /// Additional custom/unregistered JWK parameters.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// A JSON Web Key Set (JWKS) containing an array of [`JwkKey`] elements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwks {
    /// List of JSON Web Keys in this set.
    pub keys: Vec<JwkKey>,
}

impl JwkKey {
    /// Checks if this JWK key is allowed for signature verification according to `use` and `key_ops`.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::domain::JwkKey;
    ///
    /// let mut key = JwkKey {
    ///     kty: "RSA".to_string(),
    ///     key_use: Some("sig".to_string()),
    ///     key_ops: None,
    ///     alg: Some("RS256".to_string()),
    ///     kid: Some("key-1".to_string()),
    ///     n: None,
    ///     e: None,
    ///     crv: None,
    ///     x: None,
    ///     y: None,
    ///     k: None,
    ///     extra: serde_json::Map::new(),
    /// };
    ///
    /// assert!(key.allows_verification());
    ///
    /// key.key_use = Some("enc".to_string());
    /// assert!(!key.allows_verification());
    /// ```
    pub fn allows_verification(&self) -> bool {
        if self.key_use.as_deref().is_some_and(|u| u != "sig") {
            return false;
        }
        if self
            .key_ops
            .as_ref()
            .is_some_and(|ops| !ops.iter().any(|op| op == "verify"))
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_jwk_allows_verification() {
        let sig_key: JwkKey = serde_json::from_value(json!({
            "kty": "RSA",
            "use": "sig",
            "kid": "sig-key"
        }))
        .unwrap();
        assert!(sig_key.allows_verification());

        let enc_key: JwkKey = serde_json::from_value(json!({
            "kty": "RSA",
            "use": "enc",
            "kid": "enc-key"
        }))
        .unwrap();
        assert!(!enc_key.allows_verification());

        let verify_ops_key: JwkKey = serde_json::from_value(json!({
            "kty": "OKP",
            "key_ops": ["verify"],
            "kid": "ed-key"
        }))
        .unwrap();
        assert!(verify_ops_key.allows_verification());

        let sign_only_key: JwkKey = serde_json::from_value(json!({
            "kty": "OKP",
            "key_ops": ["sign"],
            "kid": "ed-key-sign"
        }))
        .unwrap();
        assert!(!sign_only_key.allows_verification());
    }
}
