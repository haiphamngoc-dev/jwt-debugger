//! Verification reports, claim validation statuses, and security warnings.

use serde::{Deserialize, Serialize};

use super::algorithm::JwtAlgorithm;
use super::error::ClaimValidationError;

/// Status outcome of the cryptographic signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Cryptographic signature is valid and matches the key.
    Valid,
    /// Cryptographic signature is invalid or could not be verified.
    Invalid,
    /// Signature verification was skipped or not performed.
    NotPerformed,
    /// The token is unsecured (`alg=none`).
    Unsecured,
}

/// Status outcome of individual or aggregate claim validation checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimCheckStatus {
    /// The claim check passed successfully.
    Valid,
    /// The claim check failed (e.g. token expired, mismatch).
    Invalid,
    /// The claim check was not performed or not requested.
    NotChecked,
    /// The claim was required but missing in the payload.
    Missing,
}

/// Detailed validation report for registered claims (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimValidationReport {
    /// Overall status of claim validation.
    pub status: ClaimCheckStatus,
    /// Status of expiration (`exp`) check.
    pub expiration: ClaimCheckStatus,
    /// Status of not-before (`nbf`) check.
    pub not_before: ClaimCheckStatus,
    /// Status of issued-at (`iat`) check.
    pub issued_at: ClaimCheckStatus,
    /// Status of issuer (`iss`) check.
    pub issuer: ClaimCheckStatus,
    /// Status of audience (`aud`) check.
    pub audience: ClaimCheckStatus,
    /// Status of subject (`sub`) check.
    pub subject: ClaimCheckStatus,
    /// Detailed list of claim validation errors encountered.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ClaimValidationError>,
}

impl Default for ClaimValidationReport {
    fn default() -> Self {
        Self {
            status: ClaimCheckStatus::NotChecked,
            expiration: ClaimCheckStatus::NotChecked,
            not_before: ClaimCheckStatus::NotChecked,
            issued_at: ClaimCheckStatus::NotChecked,
            issuer: ClaimCheckStatus::NotChecked,
            audience: ClaimCheckStatus::NotChecked,
            subject: ClaimCheckStatus::NotChecked,
            errors: Vec::new(),
        }
    }
}

/// Cryptographic signature verification outcome report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureReport {
    /// Verification status of the signature.
    pub status: SignatureStatus,
    /// Algorithm used during signature verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<JwtAlgorithm>,
    /// Type of cryptographic key used (e.g. `"Secret"`, `"RSA"`, `"EC"`, `"JWKS"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    /// Error message if signature verification failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Comprehensive verification report combining signature verification and claim validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationReport {
    /// Overall validity (`true` if both signature and required claims are valid).
    pub valid: bool,
    /// Detailed signature verification report.
    pub signature: SignatureReport,
    /// Detailed claim validation report.
    pub claims: ClaimValidationReport,
    /// Parsed JOSE header.
    pub header: serde_json::Value,
}

/// Potential security vulnerability or hygiene warning identified in the token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityWarning {
    /// Unique warning code (e.g. `"ALG_NONE"`, `"WEAK_KEY"`, `"NO_EXP"`).
    pub code: String,
    /// Human-readable explanation and recommendation.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_validation_report_default() {
        let report = ClaimValidationReport::default();
        assert_eq!(report.status, ClaimCheckStatus::NotChecked);
        assert_eq!(report.expiration, ClaimCheckStatus::NotChecked);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn test_signature_status_serialization() {
        assert_eq!(
            serde_json::to_string(&SignatureStatus::Valid).unwrap(),
            "\"valid\""
        );
        assert_eq!(
            serde_json::to_string(&SignatureStatus::NotPerformed).unwrap(),
            "\"not_performed\""
        );
    }
}
