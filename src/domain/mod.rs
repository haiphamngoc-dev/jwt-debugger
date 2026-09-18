//! Domain models and core types for JWT decoding, cryptographic algorithms, claims, JWK/JWKS, and verification.

pub mod algorithm;
pub mod claims;
pub mod error;
pub mod header;
pub mod jwk;
pub mod jwt;
pub mod verification;

pub use algorithm::{AlgorithmFamily, JwtAlgorithm};
pub use claims::{Audience, StandardClaims};
pub use error::{ClaimValidationError, CryptoError, JwksError, JwtError};
pub use header::JwtHeader;
pub use jwk::{JwkKey, Jwks};
pub use jwt::{JwtToken, MAX_HEADER_SIZE, MAX_JWKS_SIZE, MAX_PAYLOAD_SIZE, MAX_TOKEN_SIZE};
pub use verification::{
    ClaimCheckStatus, ClaimValidationReport, SecurityWarning, SignatureReport, SignatureStatus,
    VerificationReport,
};
