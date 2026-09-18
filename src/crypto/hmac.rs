//! HMAC symmetric signature verification (HS256, HS384, HS512).

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

use crate::domain::algorithm::JwtAlgorithm;
use crate::domain::error::CryptoError;

use super::keys::HmacKey;

/// Verifies an HMAC-SHA signature against the provided [`HmacKey`].
///
/// Supports `HS256` (HMAC-SHA256), `HS384` (HMAC-SHA384), and `HS512` (HMAC-SHA512).
///
/// # Arguments
///
/// * `algorithm` - Must be `HS256`, `HS384`, or `HS512`.
/// * `signing_input` - The raw signing input bytes (`header.payload`).
/// * `signature` - The raw signature bytes to verify.
/// * `key` - The symmetric secret key.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSignature`] if signature is invalid,
/// [`CryptoError::InvalidSecret`] if key slice is invalid, or
/// [`CryptoError::UnsupportedAlgorithm`] if algorithm is not HMAC.
///
/// # Examples
///
/// ```
/// use jwt_debugger::crypto::hmac::verify_hmac;
/// use jwt_debugger::crypto::HmacKey;
/// use jwt_debugger::domain::JwtAlgorithm;
///
/// let key = HmacKey::new(b"secret".to_vec());
/// // Invalid signature check
/// assert!(verify_hmac(JwtAlgorithm::HS256, b"test", b"invalid-sig", &key).is_err());
/// ```
pub fn verify_hmac(
    algorithm: JwtAlgorithm,
    signing_input: &[u8],
    signature: &[u8],
    key: &HmacKey,
) -> Result<(), CryptoError> {
    match algorithm {
        JwtAlgorithm::HS256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
                .map_err(|e| CryptoError::InvalidSecret(e.to_string()))?;
            mac.update(signing_input);
            mac.verify_slice(signature)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        JwtAlgorithm::HS384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(key.as_bytes())
                .map_err(|e| CryptoError::InvalidSecret(e.to_string()))?;
            mac.update(signing_input);
            mac.verify_slice(signature)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        JwtAlgorithm::HS512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key.as_bytes())
                .map_err(|e| CryptoError::InvalidSecret(e.to_string()))?;
            mac.update(signing_input);
            mac.verify_slice(signature)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_verification() {
        let key = HmacKey::new(b"secret".to_vec());
        let data = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";

        // Generate expected HMAC
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(data);
        let expected_sig = mac.finalize().into_bytes();

        assert!(verify_hmac(JwtAlgorithm::HS256, data, &expected_sig, &key).is_ok());
        assert!(verify_hmac(JwtAlgorithm::HS256, data, b"bad signature bytes...", &key).is_err());
    }

    #[test]
    fn test_hmac_sha384_and_sha512() {
        let key = HmacKey::new(b"secret".to_vec());
        let data = b"payload.test";

        let mut mac384 = Hmac::<Sha384>::new_from_slice(key.as_bytes()).unwrap();
        mac384.update(data);
        let sig384 = mac384.finalize().into_bytes();
        assert!(verify_hmac(JwtAlgorithm::HS384, data, &sig384, &key).is_ok());

        let mut mac512 = Hmac::<Sha512>::new_from_slice(key.as_bytes()).unwrap();
        mac512.update(data);
        let sig512 = mac512.finalize().into_bytes();
        assert!(verify_hmac(JwtAlgorithm::HS512, data, &sig512, &key).is_ok());
    }
}
