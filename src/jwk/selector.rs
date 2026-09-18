//! Key selection and validation logic from a JWKS for token verification.

use crate::crypto::keys::VerificationKey;
use crate::domain::algorithm::JwtAlgorithm;
use crate::domain::error::JwksError;
use crate::domain::jwk::{JwkKey, Jwks};

use super::converter::jwk_to_verification_key;

/// Selects and validates a compatible [`VerificationKey`] from a [`Jwks`] for a given algorithm and optional `kid`.
///
/// Selection rules:
/// 1. If `kid` is provided: Searches the JWKS for an exact match.
/// 2. If `kid` is not provided: Scans all keys in the JWKS for compatibility.
///    - If exactly 1 compatible key is found, returns it.
///    - If multiple compatible keys are found, returns [`JwksError::AmbiguousKey`].
///    - If 0 compatible keys are found, returns [`JwksError::NoCompatibleKey`].
/// 3. Validates that the selected key allows verification (`use="sig"`, `key_ops` includes `"verify"`, matching `alg`).
///
/// # Arguments
///
/// * `jwks` - The JWK Set.
/// * `kid` - Optional Key ID from the token's JOSE header.
/// * `expected_alg` - The algorithm required for token verification.
///
/// # Errors
///
/// Returns [`JwksError`] if no key matches, key is incompatible, or multiple keys are ambiguous.
///
/// # Examples
///
/// ```
/// use jwt_debugger::domain::jwk::Jwks;
/// use jwt_debugger::domain::JwtAlgorithm;
/// use jwt_debugger::jwk::{parse_jwks, select_jwk};
///
/// let jwks = parse_jwks(r#"{
///     "keys": [
///         { "kty": "oct", "k": "c2VjcmV0MTIz", "kid": "key-1", "use": "sig", "alg": "HS256" }
///     ]
/// }"#).unwrap();
///
/// let key = select_jwk(&jwks, Some("key-1"), JwtAlgorithm::HS256).unwrap();
/// assert_eq!(key.key_type_name(), "oct (HMAC Secret)");
/// ```
pub fn select_jwk(
    jwks: &Jwks,
    kid: Option<&str>,
    expected_alg: JwtAlgorithm,
) -> Result<VerificationKey, JwksError> {
    if let Some(token_kid) = kid {
        // Safe string comparison for kid
        let matching_jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(token_kid))
            .ok_or_else(|| JwksError::KeyNotFound(token_kid.to_string()))?;

        validate_and_convert_jwk(matching_jwk, expected_alg)
    } else {
        // No kid provided in token. Find all compatible keys in JWKS
        let mut compatible_keys = Vec::new();
        for key in &jwks.keys {
            if let Ok(ver_key) = validate_and_convert_jwk(key, expected_alg) {
                compatible_keys.push(ver_key);
            }
        }

        match compatible_keys.len() {
            0 => Err(JwksError::NoCompatibleKey(expected_alg.to_string())),
            1 => Ok(compatible_keys.remove(0)),
            _ => Err(JwksError::AmbiguousKey),
        }
    }
}

fn validate_and_convert_jwk(
    jwk: &JwkKey,
    expected_alg: JwtAlgorithm,
) -> Result<VerificationKey, JwksError> {
    if !jwk.allows_verification() {
        return Err(JwksError::IncompatibleKey {
            kid: jwk.kid.clone().unwrap_or_else(|| "unknown".to_string()),
            reason: "JWK 'use' or 'key_ops' does not allow signature verification".to_string(),
        });
    }

    if jwk
        .alg
        .as_deref()
        .is_some_and(|alg_str| alg_str != expected_alg.as_str())
    {
        return Err(JwksError::IncompatibleKey {
            kid: jwk.kid.clone().unwrap_or_else(|| "unknown".to_string()),
            reason: format!(
                "JWK specified alg '{}' which does not match expected algorithm '{expected_alg}'",
                jwk.alg.as_deref().unwrap_or("")
            ),
        });
    }

    let ver_key = jwk_to_verification_key(jwk).map_err(|e| JwksError::IncompatibleKey {
        kid: jwk.kid.clone().unwrap_or_else(|| "unknown".to_string()),
        reason: e.to_string(),
    })?;

    ver_key
        .is_compatible_with(expected_alg)
        .map_err(|e| JwksError::IncompatibleKey {
            kid: jwk.kid.clone().unwrap_or_else(|| "unknown".to_string()),
            reason: e.to_string(),
        })?;

    Ok(ver_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::parser::parse_jwks;

    #[test]
    fn test_select_jwk_matching_kid() {
        let jwks = parse_jwks(
            r#"{
            "keys": [
                { "kty": "oct", "k": "c2VjcmV0MQ", "kid": "key-1", "use": "sig", "alg": "HS256" },
                { "kty": "oct", "k": "c2VjcmV0Mg", "kid": "key-2", "use": "sig", "alg": "HS256" }
            ]
        }"#,
        )
        .unwrap();

        let key = select_jwk(&jwks, Some("key-2"), JwtAlgorithm::HS256).unwrap();
        match key {
            VerificationKey::Hmac(hmac) => assert_eq!(hmac.as_bytes(), b"secret2"),
            _ => panic!("Expected HMAC key"),
        }
    }

    #[test]
    fn test_select_jwk_key_not_found() {
        let jwks = parse_jwks(r#"{"keys":[]}"#).unwrap();
        let err = select_jwk(&jwks, Some("missing-key"), JwtAlgorithm::HS256).unwrap_err();
        match err {
            JwksError::KeyNotFound(kid) => assert_eq!(kid, "missing-key"),
            _ => panic!("Expected KeyNotFound error"),
        }
    }

    #[test]
    fn test_select_jwk_ambiguous_without_kid() {
        let jwks = parse_jwks(
            r#"{
            "keys": [
                { "kty": "oct", "k": "c2VjcmV0MQ", "kid": "key-1", "use": "sig", "alg": "HS256" },
                { "kty": "oct", "k": "c2VjcmV0Mg", "kid": "key-2", "use": "sig", "alg": "HS256" }
            ]
        }"#,
        )
        .unwrap();

        let err = select_jwk(&jwks, None, JwtAlgorithm::HS256).unwrap_err();
        assert!(matches!(err, JwksError::AmbiguousKey));
    }
}
