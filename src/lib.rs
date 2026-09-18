pub mod application;
pub mod cli;
pub mod crypto;
pub mod domain;
pub mod infrastructure;
pub mod jwk;
pub mod utils;

// Re-export high-level types for public library usage
pub use application::{
    ClaimValidationOptions, DecodedJwtReport, InspectionReport, decode_jwt, decode_signature_only,
    inspect_jwt, validate_claims, verify_jwt,
};
pub use crypto::keys::{HmacKey, SecretEncoding, VerificationKey};
pub use crypto::verifier::{VerificationOptions, verify_signature};
pub use domain::algorithm::{AlgorithmFamily, JwtAlgorithm};
pub use domain::claims::{Audience, StandardClaims};
pub use domain::error::{ClaimValidationError, CryptoError, JwksError, JwtError};
pub use domain::header::JwtHeader;
pub use domain::jwk::{JwkKey, Jwks};
pub use domain::jwt::JwtToken;
pub use domain::verification::{
    ClaimCheckStatus, ClaimValidationReport, SecurityWarning, SignatureReport, SignatureStatus,
    VerificationReport,
};
