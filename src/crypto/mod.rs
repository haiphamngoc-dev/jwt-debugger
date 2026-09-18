//! Cryptographic engine supporting HMAC, RSA (PKCS#1 & PSS), ECDSA, and EdDSA signature verification.

pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod keys;
pub mod rsa;
pub mod verifier;

pub use keys::{
    EcPublicKey, Ed25519PublicKey, HmacKey, RsaPublicKey, SecretEncoding, VerificationKey,
};
pub use verifier::{VerificationOptions, verify_signature};
