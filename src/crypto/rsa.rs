//! RSA signature verification supporting RSASSA-PKCS1-v1_5 (RS256, RS384, RS512) and RSASSA-PSS (PS256, PS384, PS512).

use rsa::pkcs1v15::VerifyingKey as Pkcs1v15VerifyingKey;
use rsa::pss::VerifyingKey as PssVerifyingKey;
use rsa::signature::Verifier;
use sha2::{Sha256, Sha384, Sha512};

use crate::domain::algorithm::JwtAlgorithm;
use crate::domain::error::CryptoError;

use super::keys::RsaPublicKey;

/// Verifies an RSA signature (PKCS#1 v1.5 or PSS) against the provided [`RsaPublicKey`].
///
/// Supports:
/// - `RS256`, `RS384`, `RS512` (PKCS#1 v1.5)
/// - `PS256`, `PS384`, `PS512` (RSA-PSS with MGF1)
///
/// # Arguments
///
/// * `algorithm` - The RSA algorithm to use for verification.
/// * `signing_input` - The raw signing input bytes (`header.payload`).
/// * `signature` - The raw RSA signature bytes.
/// * `key` - The RSA public key.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSignature`] if verification fails, or
/// [`CryptoError::UnsupportedAlgorithm`] if algorithm is not RSA.
pub fn verify_rsa(
    algorithm: JwtAlgorithm,
    signing_input: &[u8],
    signature: &[u8],
    key: &RsaPublicKey,
) -> Result<(), CryptoError> {
    match algorithm {
        // RSASSA-PKCS1-v1_5
        JwtAlgorithm::RS256 => {
            let verifying_key = Pkcs1v15VerifyingKey::<Sha256>::new(key.0.clone());
            let rsa_sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| CryptoError::InvalidSignature)?;
            verifying_key
                .verify(signing_input, &rsa_sig)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        JwtAlgorithm::RS384 => {
            let verifying_key = Pkcs1v15VerifyingKey::<Sha384>::new(key.0.clone());
            let rsa_sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| CryptoError::InvalidSignature)?;
            verifying_key
                .verify(signing_input, &rsa_sig)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        JwtAlgorithm::RS512 => {
            let verifying_key = Pkcs1v15VerifyingKey::<Sha512>::new(key.0.clone());
            let rsa_sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| CryptoError::InvalidSignature)?;
            verifying_key
                .verify(signing_input, &rsa_sig)
                .map_err(|_| CryptoError::InvalidSignature)
        }

        // RSASSA-PSS
        JwtAlgorithm::PS256 => {
            let verifying_key = PssVerifyingKey::<Sha256>::new(key.0.clone());
            let rsa_sig = rsa::pss::Signature::try_from(signature)
                .map_err(|_| CryptoError::InvalidSignature)?;
            verifying_key
                .verify(signing_input, &rsa_sig)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        JwtAlgorithm::PS384 => {
            let verifying_key = PssVerifyingKey::<Sha384>::new(key.0.clone());
            let rsa_sig = rsa::pss::Signature::try_from(signature)
                .map_err(|_| CryptoError::InvalidSignature)?;
            verifying_key
                .verify(signing_input, &rsa_sig)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        JwtAlgorithm::PS512 => {
            let verifying_key = PssVerifyingKey::<Sha512>::new(key.0.clone());
            let rsa_sig = rsa::pss::Signature::try_from(signature)
                .map_err(|_| CryptoError::InvalidSignature)?;
            verifying_key
                .verify(signing_input, &rsa_sig)
                .map_err(|_| CryptoError::InvalidSignature)
        }

        _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}
