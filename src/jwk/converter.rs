//! Conversion of JSON Web Keys (JWK) into strongly-typed [`VerificationKey`] instances.

use rsa::BigUint;
use rsa::RsaPublicKey as InnerRsaKey;

use crate::crypto::keys::{EcPublicKey, Ed25519PublicKey, HmacKey, RsaPublicKey, VerificationKey};
use crate::domain::error::CryptoError;
use crate::domain::jwk::JwkKey;
use crate::utils::base64url::decode_base64url;

/// Converts a domain [`JwkKey`] into a cryptographic [`VerificationKey`].
///
/// Supports:
/// - `RSA`: Reads modulus `n` and public exponent `e`.
/// - `EC`: Reads curve `crv` (`P-256` or `P-384`) and affine coordinates `x`, `y`.
/// - `OKP`: Reads curve `crv` (`Ed25519`) and public key point `x`.
/// - `oct`: Reads symmetric shared secret `k`.
///
/// # Arguments
///
/// * `jwk` - The domain JWK structure.
///
/// # Errors
///
/// Returns [`CryptoError`] if required parameters are missing, coordinates or moduli are invalid,
/// or the key type/curve is unsupported.
///
/// # Examples
///
/// ```
/// use jwt_debugger::domain::JwkKey;
/// use jwt_debugger::jwk::jwk_to_verification_key;
///
/// let jwk: JwkKey = serde_json::from_str(r#"{
///     "kty": "oct",
///     "k": "c2VjcmV0"
/// }"#).unwrap();
///
/// let key = jwk_to_verification_key(&jwk).unwrap();
/// assert_eq!(key.key_type_name(), "oct (HMAC Secret)");
/// ```
pub fn jwk_to_verification_key(jwk: &JwkKey) -> Result<VerificationKey, CryptoError> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n_str = jwk.n.as_deref().ok_or_else(|| {
                CryptoError::InvalidRsaKey("JWK RSA key missing modulus 'n'".to_string())
            })?;
            let e_str = jwk.e.as_deref().ok_or_else(|| {
                CryptoError::InvalidRsaKey("JWK RSA key missing exponent 'e'".to_string())
            })?;

            let n_bytes = decode_base64url(n_str).map_err(|e| {
                CryptoError::InvalidRsaKey(format!("Invalid Base64URL in RSA 'n': {e}"))
            })?;
            let e_bytes = decode_base64url(e_str).map_err(|e| {
                CryptoError::InvalidRsaKey(format!("Invalid Base64URL in RSA 'e': {e}"))
            })?;

            let n = BigUint::from_bytes_be(&n_bytes);
            let e = BigUint::from_bytes_be(&e_bytes);

            let rsa_pub = InnerRsaKey::new(n, e).map_err(|e| {
                CryptoError::InvalidRsaKey(format!("Invalid RSA modulus/exponent: {e}"))
            })?;

            Ok(VerificationKey::Rsa(RsaPublicKey(rsa_pub)))
        }

        "EC" => {
            let crv = jwk.crv.as_deref().ok_or_else(|| {
                CryptoError::InvalidEcKey("JWK EC key missing curve 'crv'".to_string())
            })?;
            let x_str = jwk.x.as_deref().ok_or_else(|| {
                CryptoError::InvalidEcKey("JWK EC key missing coordinate 'x'".to_string())
            })?;
            let y_str = jwk.y.as_deref().ok_or_else(|| {
                CryptoError::InvalidEcKey("JWK EC key missing coordinate 'y'".to_string())
            })?;

            let x_bytes = decode_base64url(x_str).map_err(|e| {
                CryptoError::InvalidEcKey(format!("Invalid Base64URL in EC 'x': {e}"))
            })?;
            let y_bytes = decode_base64url(y_str).map_err(|e| {
                CryptoError::InvalidEcKey(format!("Invalid Base64URL in EC 'y': {e}"))
            })?;

            match crv {
                "P-256" | "secp256r1" => {
                    if x_bytes.len() != 32 || y_bytes.len() != 32 {
                        return Err(CryptoError::InvalidEcKey(
                            "Invalid coordinate length for P-256 (expected 32 bytes each)"
                                .to_string(),
                        ));
                    }
                    let mut sec1 = Vec::with_capacity(1 + 32 + 32);
                    sec1.push(0x04);
                    sec1.extend_from_slice(&x_bytes);
                    sec1.extend_from_slice(&y_bytes);

                    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| {
                        CryptoError::InvalidEcKey(format!("Invalid P-256 point: {e}"))
                    })?;
                    Ok(VerificationKey::Ec(EcPublicKey::P256(key)))
                }
                "P-384" | "secp384r1" => {
                    if x_bytes.len() != 48 || y_bytes.len() != 48 {
                        return Err(CryptoError::InvalidEcKey(
                            "Invalid coordinate length for P-384 (expected 48 bytes each)"
                                .to_string(),
                        ));
                    }
                    let mut sec1 = Vec::with_capacity(1 + 48 + 48);
                    sec1.push(0x04);
                    sec1.extend_from_slice(&x_bytes);
                    sec1.extend_from_slice(&y_bytes);

                    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| {
                        CryptoError::InvalidEcKey(format!("Invalid P-384 point: {e}"))
                    })?;
                    Ok(VerificationKey::Ec(EcPublicKey::P384(key)))
                }
                other => Err(CryptoError::CurveMismatch {
                    algorithm: "ECDSA".to_string(),
                    expected_curve: "P-256 or P-384".to_string(),
                    actual_curve: other.to_string(),
                }),
            }
        }

        "OKP" => {
            let crv = jwk.crv.as_deref().ok_or_else(|| {
                CryptoError::InvalidEdKey("JWK OKP key missing curve 'crv'".to_string())
            })?;
            let x_str = jwk.x.as_deref().ok_or_else(|| {
                CryptoError::InvalidEdKey("JWK OKP key missing coordinate 'x'".to_string())
            })?;

            if crv != "Ed25519" {
                return Err(CryptoError::CurveMismatch {
                    algorithm: "EdDSA".to_string(),
                    expected_curve: "Ed25519".to_string(),
                    actual_curve: crv.to_string(),
                });
            }

            let x_bytes = decode_base64url(x_str).map_err(|e| {
                CryptoError::InvalidEdKey(format!("Invalid Base64URL in OKP 'x': {e}"))
            })?;

            if x_bytes.len() != 32 {
                return Err(CryptoError::InvalidEdKey(
                    "Invalid public key length for Ed25519 (expected 32 bytes)".to_string(),
                ));
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&x_bytes);

            let key = ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|e| {
                CryptoError::InvalidEdKey(format!("Invalid Ed25519 public key bytes: {e}"))
            })?;

            Ok(VerificationKey::Ed25519(Ed25519PublicKey(key)))
        }

        "oct" => {
            let k_str = jwk.k.as_deref().ok_or_else(|| {
                CryptoError::InvalidSecret("JWK oct key missing secret 'k'".to_string())
            })?;
            let k_bytes = decode_base64url(k_str).map_err(|e| {
                CryptoError::InvalidSecret(format!("Invalid Base64URL in oct 'k': {e}"))
            })?;
            Ok(VerificationKey::Hmac(HmacKey::new(k_bytes)))
        }

        other => Err(CryptoError::UnsupportedAlgorithm(format!(
            "Unsupported JWK kty: '{other}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_convert_oct_jwk() {
        let jwk: JwkKey = serde_json::from_value(json!({
            "kty": "oct",
            "k": "c2VjcmV0MTIz"
        }))
        .unwrap();

        let key = jwk_to_verification_key(&jwk).unwrap();
        match key {
            VerificationKey::Hmac(hmac) => assert_eq!(hmac.as_bytes(), b"secret123"),
            _ => panic!("Expected HMAC key"),
        }
    }

    #[test]
    fn test_convert_ec_p256_jwk() {
        use crate::utils::base64url::encode_base64url;
        use p256::ecdsa::SigningKey;

        let signing_key = SigningKey::from_slice(&[42u8; 32]).unwrap();
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x_b64 = encode_base64url(point.x().unwrap());
        let y_b64 = encode_base64url(point.y().unwrap());

        let jwk: JwkKey = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64
        }))
        .unwrap();

        let key = jwk_to_verification_key(&jwk).unwrap();
        assert_eq!(key.key_type_name(), "EC Public Key (P-256)");
    }

    #[test]
    fn test_convert_okp_ed25519_jwk() {
        // RFC 8037 Ed25519 public key
        let jwk: JwkKey = serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }))
        .unwrap();

        let key = jwk_to_verification_key(&jwk).unwrap();
        assert_eq!(key.key_type_name(), "OKP Public Key (Ed25519)");
    }
}
