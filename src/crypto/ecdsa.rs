//! ECDSA signature verification for NIST curves P-256 (ES256) and P-384 (ES384).

use p256::ecdsa::signature::Verifier;

use crate::domain::algorithm::JwtAlgorithm;
use crate::domain::error::CryptoError;

use super::keys::EcPublicKey;

/// Verifies an ECDSA signature in IEEE P1363 (R || S) format against an [`EcPublicKey`].
///
/// Supports:
/// - `ES256` (P-256 curve, 64-byte signature)
/// - `ES384` (P-384 curve, 96-byte signature)
///
/// # Arguments
///
/// * `algorithm` - Must match the curve of the public key.
/// * `signing_input` - The raw signing input bytes (`header.payload`).
/// * `signature` - The raw IEEE P1363 signature bytes.
/// * `key` - The ECDSA public key.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSignature`] if signature is invalid,
/// [`CryptoError::CurveMismatch`] if algorithm curve does not match key curve, or
/// [`CryptoError::UnsupportedAlgorithm`] if algorithm is not ECDSA.
pub fn verify_ecdsa(
    algorithm: JwtAlgorithm,
    signing_input: &[u8],
    signature: &[u8],
    key: &EcPublicKey,
) -> Result<(), CryptoError> {
    match (algorithm, key) {
        (JwtAlgorithm::ES256, EcPublicKey::P256(verifying_key)) => {
            // JWS ECDSA signature is IEEE P1363 (R || S) 64 bytes for ES256
            let sig = p256::ecdsa::Signature::try_from(signature)
                .map_err(|_| CryptoError::InvalidSignature)?;
            verifying_key
                .verify(signing_input, &sig)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        (JwtAlgorithm::ES384, EcPublicKey::P384(verifying_key)) => {
            // JWS ECDSA signature is IEEE P1363 (R || S) 96 bytes for ES384
            let sig = p384::ecdsa::Signature::try_from(signature)
                .map_err(|_| CryptoError::InvalidSignature)?;
            verifying_key
                .verify(signing_input, &sig)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        (JwtAlgorithm::ES256, EcPublicKey::P384(_)) => Err(CryptoError::CurveMismatch {
            algorithm: "ES256".to_string(),
            expected_curve: "P-256".to_string(),
            actual_curve: "P-384".to_string(),
        }),
        (JwtAlgorithm::ES384, EcPublicKey::P256(_)) => Err(CryptoError::CurveMismatch {
            algorithm: "ES384".to_string(),
            expected_curve: "P-384".to_string(),
            actual_curve: "P-256".to_string(),
        }),
        _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}
