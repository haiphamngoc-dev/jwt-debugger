//! Verification key representations, zeroized HMAC secrets, public key wrappers, and PEM parsers.

use pkcs8::DecodePublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
use std::fmt;
use zeroize::Zeroizing;

use crate::domain::algorithm::{AlgorithmFamily, JwtAlgorithm};
use crate::domain::error::CryptoError;
use crate::utils::base64url::decode_base64url;

/// Zeroized wrapper for symmetric HMAC secrets to prevent secret leakage in logs or memory.
#[derive(Clone)]
pub struct HmacKey(Zeroizing<Vec<u8>>);

impl HmacKey {
    /// Constructs a new [`HmacKey`] from raw secret bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw secret byte vector.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Returns the underlying secret as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HmacKey([REDACTED])")
    }
}

/// Encoding format of the symmetric secret string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretEncoding {
    /// Plain UTF-8 encoded string.
    Utf8,
    /// Hexadecimal (base16) encoded string.
    Hex,
    /// Standard Base64 encoded string.
    Base64,
    /// URL-safe unpadded/padded Base64URL encoded string.
    Base64Url,
}

impl HmacKey {
    /// Decodes an HMAC secret string based on the specified [`SecretEncoding`].
    ///
    /// # Arguments
    ///
    /// * `raw` - The raw encoded secret string.
    /// * `encoding` - The expected encoding format.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidSecret`] if decoding fails or the decoded secret is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::crypto::{HmacKey, SecretEncoding};
    ///
    /// let key = HmacKey::from_encoded("my-secret-key", SecretEncoding::Utf8).unwrap();
    /// assert_eq!(key.as_bytes(), b"my-secret-key");
    ///
    /// let hex_key = HmacKey::from_encoded("68656c6c6f", SecretEncoding::Hex).unwrap();
    /// assert_eq!(hex_key.as_bytes(), b"hello");
    /// ```
    pub fn from_encoded(raw: &str, encoding: SecretEncoding) -> Result<Self, CryptoError> {
        let trimmed = raw.trim();
        let bytes = match encoding {
            SecretEncoding::Utf8 => raw.as_bytes().to_vec(),
            SecretEncoding::Hex => hex::decode(trimmed)
                .map_err(|e| CryptoError::InvalidSecret(format!("Invalid hex string: {e}")))?,
            SecretEncoding::Base64 => {
                use base64::Engine;
                use base64::engine::general_purpose::STANDARD;
                STANDARD.decode(trimmed).map_err(|e| {
                    CryptoError::InvalidSecret(format!("Invalid Base64 string: {e}"))
                })?
            }
            SecretEncoding::Base64Url => decode_base64url(trimmed).map_err(|e| {
                CryptoError::InvalidSecret(format!("Invalid Base64URL string: {e}"))
            })?,
        };

        if bytes.is_empty() {
            return Err(CryptoError::InvalidSecret(
                "Secret cannot be empty".to_string(),
            ));
        }

        Ok(Self::new(bytes))
    }
}

/// RSA public key wrapper for PKCS#1 v1.5 and RSA-PSS signature verification.
#[derive(Clone)]
pub struct RsaPublicKey(pub rsa::RsaPublicKey);

impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RsaPublicKey({} bits)", self.0.size() * 8)
    }
}

/// ECDSA public verifying key for NIST curves P-256 and P-384.
#[derive(Clone)]
pub enum EcPublicKey {
    /// NIST P-256 (secp256r1 / prime256v1) curve key for ES256.
    P256(p256::ecdsa::VerifyingKey),
    /// NIST P-384 (secp384r1) curve key for ES384.
    P384(p384::ecdsa::VerifyingKey),
}

impl fmt::Debug for EcPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::P256(_) => write!(f, "EcPublicKey(P-256)"),
            Self::P384(_) => write!(f, "EcPublicKey(P-384)"),
        }
    }
}

/// Ed25519 public verifying key for EdDSA signatures.
#[derive(Clone)]
pub struct Ed25519PublicKey(pub ed25519_dalek::VerifyingKey);

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519PublicKey")
    }
}

/// Strongly-typed container for cryptographic verification keys.
#[derive(Clone, Debug)]
pub enum VerificationKey {
    /// Symmetric HMAC key.
    Hmac(HmacKey),
    /// Asymmetric RSA public key.
    Rsa(RsaPublicKey),
    /// Asymmetric ECDSA public key.
    Ec(EcPublicKey),
    /// Asymmetric Ed25519 public key.
    Ed25519(Ed25519PublicKey),
    /// Unsecured token verification marker.
    Unsecured,
}

impl VerificationKey {
    /// Returns a human-friendly name of the key type for display and error reporting.
    pub fn key_type_name(&self) -> &'static str {
        match self {
            Self::Hmac(_) => "oct (HMAC Secret)",
            Self::Rsa(_) => "RSA Public Key",
            Self::Ec(EcPublicKey::P256(_)) => "EC Public Key (P-256)",
            Self::Ec(EcPublicKey::P384(_)) => "EC Public Key (P-384)",
            Self::Ed25519(_) => "OKP Public Key (Ed25519)",
            Self::Unsecured => "None (Unsecured)",
        }
    }

    /// Validates whether the key type is compatible with the given [`JwtAlgorithm`].
    ///
    /// # Arguments
    ///
    /// * `alg` - The algorithm to check compatibility against.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyTypeMismatch`] if the key type cannot be used with the algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::crypto::{HmacKey, VerificationKey};
    /// use jwt_debugger::domain::JwtAlgorithm;
    ///
    /// let key = VerificationKey::Hmac(HmacKey::new(b"secret".to_vec()));
    /// assert!(key.is_compatible_with(JwtAlgorithm::HS256).is_ok());
    /// assert!(key.is_compatible_with(JwtAlgorithm::RS256).is_err());
    /// ```
    pub fn is_compatible_with(&self, alg: JwtAlgorithm) -> Result<(), CryptoError> {
        let alg_family = alg.family();
        let key_matches = match (self, alg_family) {
            (Self::Hmac(_), AlgorithmFamily::Hmac) => true,
            (Self::Rsa(_), AlgorithmFamily::RsaPkcs1 | AlgorithmFamily::RsaPss) => true,
            (Self::Ec(EcPublicKey::P256(_)), AlgorithmFamily::Ecdsa) => alg == JwtAlgorithm::ES256,
            (Self::Ec(EcPublicKey::P384(_)), AlgorithmFamily::Ecdsa) => alg == JwtAlgorithm::ES384,
            (Self::Ed25519(_), AlgorithmFamily::Eddsa) => alg == JwtAlgorithm::EdDSA,
            (Self::Unsecured, AlgorithmFamily::None) => true,
            _ => false,
        };

        if !key_matches {
            return Err(CryptoError::KeyTypeMismatch {
                algorithm: alg.to_string(),
                key_type: self.key_type_name().to_string(),
            });
        }

        Ok(())
    }

    /// Parses an asymmetric public key from PEM string (supports PKCS#8 SPKI, PKCS#1 RSA, SEC1 EC, and Ed25519 SPKI).
    ///
    /// # Arguments
    ///
    /// * `pem_str` - PEM-formatted public key string.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidPem`] if parsing fails for all supported formats.
    pub fn from_pem(pem_str: &str) -> Result<Self, CryptoError> {
        let trimmed = pem_str.trim();

        // 1. Try RSA (PKCS#8 SPKI or PKCS#1)
        if let Ok(rsa_key) = rsa::RsaPublicKey::from_public_key_pem(trimmed) {
            return Ok(Self::Rsa(RsaPublicKey(rsa_key)));
        }
        if let Ok(rsa_key) = rsa::RsaPublicKey::from_pkcs1_pem(trimmed) {
            return Ok(Self::Rsa(RsaPublicKey(rsa_key)));
        }

        // 2. Try ECDSA P-256 (PKCS#8 SPKI)
        if let Ok(p256_key) = p256::ecdsa::VerifyingKey::from_public_key_pem(trimmed) {
            return Ok(Self::Ec(EcPublicKey::P256(p256_key)));
        }

        // 3. Try ECDSA P-384 (PKCS#8 SPKI)
        if let Ok(p384_key) = p384::ecdsa::VerifyingKey::from_public_key_pem(trimmed) {
            return Ok(Self::Ec(EcPublicKey::P384(p384_key)));
        }

        // 4. Try Ed25519 (PKCS#8 SPKI)
        if let Ok(ed_key) = ed25519_dalek::VerifyingKey::from_public_key_pem(trimmed) {
            return Ok(Self::Ed25519(Ed25519PublicKey(ed_key)));
        }

        Err(CryptoError::InvalidPem(
            "Could not parse PEM as a valid RSA, ECDSA (P-256/P-384), or Ed25519 public key. Supported formats: PKCS#8 SPKI PEM, PKCS#1 RSA PEM".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_key_encodings() {
        let utf8_key = HmacKey::from_encoded("secret123", SecretEncoding::Utf8).unwrap();
        assert_eq!(utf8_key.as_bytes(), b"secret123");

        let hex_key = HmacKey::from_encoded("736563726574", SecretEncoding::Hex).unwrap();
        assert_eq!(hex_key.as_bytes(), b"secret");

        let b64_key = HmacKey::from_encoded("c2VjcmV0", SecretEncoding::Base64).unwrap();
        assert_eq!(b64_key.as_bytes(), b"secret");

        let b64url_key = HmacKey::from_encoded("c2VjcmV0", SecretEncoding::Base64Url).unwrap();
        assert_eq!(b64url_key.as_bytes(), b"secret");

        assert!(HmacKey::from_encoded("", SecretEncoding::Utf8).is_err());
        assert!(HmacKey::from_encoded("not-valid-hex", SecretEncoding::Hex).is_err());
    }

    #[test]
    fn test_key_compatibility() {
        let hmac = VerificationKey::Hmac(HmacKey::new(b"secret".to_vec()));
        assert!(hmac.is_compatible_with(JwtAlgorithm::HS256).is_ok());
        assert!(hmac.is_compatible_with(JwtAlgorithm::HS384).is_ok());
        assert!(hmac.is_compatible_with(JwtAlgorithm::HS512).is_ok());
        assert!(hmac.is_compatible_with(JwtAlgorithm::RS256).is_err());
        assert!(hmac.is_compatible_with(JwtAlgorithm::ES256).is_err());
    }
}
