//! EdDSA signature verification using Ed25519 (RFC 8037).

use ed25519_dalek::Verifier;

use crate::domain::algorithm::JwtAlgorithm;
use crate::domain::error::CryptoError;

use super::keys::Ed25519PublicKey;

/// Verifies an EdDSA / Ed25519 signature against an [`Ed25519PublicKey`].
///
/// # Arguments
///
/// * `algorithm` - Must be [`JwtAlgorithm::EdDSA`].
/// * `signing_input` - The raw signing input bytes (`header.payload`).
/// * `signature` - The raw 64-byte Ed25519 signature.
/// * `key` - The Ed25519 public key.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSignature`] if signature length is not 64 bytes or
/// if verification fails, or [`CryptoError::UnsupportedAlgorithm`] if algorithm is not EdDSA.
pub fn verify_eddsa(
    algorithm: JwtAlgorithm,
    signing_input: &[u8],
    signature: &[u8],
    key: &Ed25519PublicKey,
) -> Result<(), CryptoError> {
    if algorithm != JwtAlgorithm::EdDSA {
        return Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string()));
    }

    if signature.len() != 64 {
        return Err(CryptoError::InvalidSignature);
    }

    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| CryptoError::InvalidSignature)?;

    key.0
        .verify(signing_input, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}
