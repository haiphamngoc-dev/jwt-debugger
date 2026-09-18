//! Cryptographic signature verification orchestrator with algorithm confusion protection.

use crate::domain::algorithm::JwtAlgorithm;
use crate::domain::error::CryptoError;

use super::ecdsa::verify_ecdsa;
use super::eddsa::verify_eddsa;
use super::hmac::verify_hmac;
use super::keys::VerificationKey;
use super::rsa::verify_rsa;

/// Verification configuration options.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerificationOptions {
    /// If `true`, allow tokens with `alg=none` (unsecured). Default is `false`.
    pub allow_unsecured: bool,
}

/// Verifies a JWT signature against the provided [`VerificationKey`] and expected algorithm.
///
/// Implements strict **Algorithm Confusion Protection** by verifying that the expected
/// algorithm matches the token's header `alg`, the key type matches the algorithm family,
/// and rejecting `alg=none` unless explicitly allowed via [`VerificationOptions`].
///
/// # Arguments
///
/// * `expected_algorithm` - The expected algorithm (e.g. from CLI or key type).
/// * `token_algorithm` - The algorithm specified in the token's JOSE header.
/// * `signing_input` - The raw ASCII bytes of `BASE64URL(header).BASE64URL(payload)`.
/// * `signature` - The raw decoded signature bytes.
/// * `key` - The verification key.
/// * `options` - Additional verification options.
///
/// # Errors
///
/// Returns [`CryptoError`] if algorithm mismatch, unsupported algorithm, key mismatch,
/// unsecured rejection, or cryptographic verification fails.
///
/// # Examples
///
/// ```
/// use jwt_debugger::crypto::{HmacKey, VerificationKey, VerificationOptions, verify_signature};
/// use jwt_debugger::domain::JwtAlgorithm;
///
/// let key = VerificationKey::Hmac(HmacKey::new(b"secret".to_vec()));
/// let options = VerificationOptions::default();
///
/// // Algorithm mismatch protection
/// let res = verify_signature(
///     JwtAlgorithm::RS256,
///     JwtAlgorithm::HS256,
///     b"header.payload",
///     b"sig",
///     &key,
///     &options,
/// );
/// assert!(res.is_err());
/// ```
pub fn verify_signature(
    expected_algorithm: JwtAlgorithm,
    token_algorithm: JwtAlgorithm,
    signing_input: &[u8],
    signature: &[u8],
    key: &VerificationKey,
    options: &VerificationOptions,
) -> Result<(), CryptoError> {
    // 1. Algorithm Confusion Protection: Expected Alg must match Header Alg
    if expected_algorithm != token_algorithm {
        return Err(CryptoError::AlgorithmMismatch {
            expected: expected_algorithm.to_string(),
            token_alg: token_algorithm.to_string(),
        });
    }

    // 2. Unsecured (alg=none) handling
    if expected_algorithm == JwtAlgorithm::None {
        if !options.allow_unsecured {
            return Err(CryptoError::UnsecuredNotAllowed);
        }
        if !signature.is_empty() {
            return Err(CryptoError::InvalidSignature);
        }
        return Ok(());
    }

    // 3. Key compatibility check
    key.is_compatible_with(expected_algorithm)?;

    // 4. Execute cryptographic verification
    match (key, expected_algorithm) {
        (VerificationKey::Hmac(hmac_key), _) if expected_algorithm.is_symmetric() => {
            verify_hmac(expected_algorithm, signing_input, signature, hmac_key)
        }
        (VerificationKey::Rsa(rsa_key), _) => {
            verify_rsa(expected_algorithm, signing_input, signature, rsa_key)
        }
        (VerificationKey::Ec(ec_key), _) => {
            verify_ecdsa(expected_algorithm, signing_input, signature, ec_key)
        }
        (VerificationKey::Ed25519(ed_key), _) => {
            verify_eddsa(expected_algorithm, signing_input, signature, ed_key)
        }
        (VerificationKey::Unsecured, _) => Err(CryptoError::UnsecuredNotAllowed),
        _ => Err(CryptoError::KeyTypeMismatch {
            algorithm: expected_algorithm.to_string(),
            key_type: key.key_type_name().to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::HmacKey;

    #[test]
    fn test_algorithm_confusion_protection() {
        let key = VerificationKey::Hmac(HmacKey::new(b"secret".to_vec()));
        let options = VerificationOptions::default();

        let err = verify_signature(
            JwtAlgorithm::RS256,
            JwtAlgorithm::HS256,
            b"data",
            b"sig",
            &key,
            &options,
        )
        .unwrap_err();

        assert_eq!(
            err,
            CryptoError::AlgorithmMismatch {
                expected: "RS256".to_string(),
                token_alg: "HS256".to_string(),
            }
        );
    }

    #[test]
    fn test_unsecured_token_rejected_by_default() {
        let key = VerificationKey::Unsecured;
        let options = VerificationOptions {
            allow_unsecured: false,
        };

        let err = verify_signature(
            JwtAlgorithm::None,
            JwtAlgorithm::None,
            b"data",
            b"",
            &key,
            &options,
        )
        .unwrap_err();

        assert_eq!(err, CryptoError::UnsecuredNotAllowed);
    }

    #[test]
    fn test_unsecured_token_accepted_when_allowed() {
        let key = VerificationKey::Unsecured;
        let options = VerificationOptions {
            allow_unsecured: true,
        };

        assert!(
            verify_signature(
                JwtAlgorithm::None,
                JwtAlgorithm::None,
                b"data",
                b"",
                &key,
                &options
            )
            .is_ok()
        );
    }
}
