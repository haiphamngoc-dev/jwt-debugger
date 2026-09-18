//! End-to-end token verification orchestrating cryptographic signature checking and claim validation.

use chrono::{DateTime, Utc};

use crate::crypto::keys::VerificationKey;
use crate::crypto::verifier::{VerificationOptions, verify_signature};
use crate::domain::algorithm::JwtAlgorithm;
use crate::domain::jwt::JwtToken;
use crate::domain::verification::{
    ClaimCheckStatus, SignatureReport, SignatureStatus, VerificationReport,
};

use super::validate_claims::{ClaimValidationOptions, validate_claims};

/// Verifies a [`JwtToken`]'s signature and validates its claims against given expectations.
///
/// This function performs:
/// 1. Algorithm matching and cryptographic signature validation using the provided [`VerificationKey`].
/// 2. Standard claims validation (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`) against [`ClaimValidationOptions`].
/// 3. Aggregation of overall validity status into a comprehensive [`VerificationReport`].
///
/// # Arguments
///
/// * `token` - The parsed JWT token to verify.
/// * `expected_alg` - The algorithm expected by the consumer / caller.
/// * `key` - The cryptographic verification key or secret.
/// * `verification_options` - Options for signature verification (e.g. `allow_unsecured`).
/// * `claim_options` - Rules and constraints for claim validation.
/// * `now` - The reference UTC timestamp used for temporal checks.
///
/// # Examples
///
/// ```
/// use chrono::Utc;
/// use jwt_debugger::application::{ClaimValidationOptions, verify_jwt};
/// use jwt_debugger::crypto::keys::VerificationKey;
/// use jwt_debugger::crypto::verifier::VerificationOptions;
/// use jwt_debugger::domain::{JwtAlgorithm, JwtToken};
///
/// // Unsecured token with allow_unsecured enabled
/// let token = JwtToken::parse("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.").unwrap();
/// let key = VerificationKey::Unsecured;
/// let verif_opts = VerificationOptions {
///     allow_unsecured: true,
/// };
/// let claim_opts = ClaimValidationOptions::default();
///
/// let report = verify_jwt(&token, JwtAlgorithm::None, &key, &verif_opts, &claim_opts, Utc::now());
/// assert!(report.valid);
/// ```
pub fn verify_jwt(
    token: &JwtToken,
    expected_alg: JwtAlgorithm,
    key: &VerificationKey,
    verification_options: &VerificationOptions,
    claim_options: &ClaimValidationOptions,
    now: DateTime<Utc>,
) -> VerificationReport {
    let token_alg_res = token.header.parse_algorithm();

    let sig_report = match token_alg_res {
        Ok(token_alg) => {
            let sig_res = verify_signature(
                expected_alg,
                token_alg,
                token.signing_input_bytes(),
                &token.signature_bytes,
                key,
                verification_options,
            );

            match sig_res {
                Ok(()) => {
                    if expected_alg == JwtAlgorithm::None {
                        SignatureReport {
                            status: SignatureStatus::Unsecured,
                            algorithm: Some(expected_alg),
                            key_type: Some(key.key_type_name().to_string()),
                            error: None,
                        }
                    } else {
                        SignatureReport {
                            status: SignatureStatus::Valid,
                            algorithm: Some(expected_alg),
                            key_type: Some(key.key_type_name().to_string()),
                            error: None,
                        }
                    }
                }
                Err(err) => SignatureReport {
                    status: SignatureStatus::Invalid,
                    algorithm: Some(expected_alg),
                    key_type: Some(key.key_type_name().to_string()),
                    error: Some(err.to_string()),
                },
            }
        }
        Err(err) => SignatureReport {
            status: SignatureStatus::Invalid,
            algorithm: None,
            key_type: Some(key.key_type_name().to_string()),
            error: Some(err.to_string()),
        },
    };

    // Validate claims
    let claims_report = validate_claims(&token.claims, claim_options, now);

    let is_signature_valid = sig_report.status == SignatureStatus::Valid
        || (sig_report.status == SignatureStatus::Unsecured
            && verification_options.allow_unsecured);

    let is_claims_valid = claims_report.status != ClaimCheckStatus::Invalid;

    let overall_valid = is_signature_valid && is_claims_valid;

    VerificationReport {
        valid: overall_valid,
        signature: sig_report,
        claims: claims_report,
        header: token.header_json.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HmacKey;

    #[test]
    fn test_verify_jwt_hs256_success() {
        // Token signed with secret "your-256-bit-secret"
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let token = JwtToken::parse(raw).unwrap();
        let key = VerificationKey::Hmac(HmacKey::new(b"your-256-bit-secret".to_vec()));
        let verif_opts = VerificationOptions::default();
        let claim_opts = ClaimValidationOptions::default();
        let now = DateTime::from_timestamp(1516239025, 0).unwrap();

        let report = verify_jwt(
            &token,
            JwtAlgorithm::HS256,
            &key,
            &verif_opts,
            &claim_opts,
            now,
        );

        assert!(report.valid);
        assert_eq!(report.signature.status, SignatureStatus::Valid);
    }

    #[test]
    fn test_verify_jwt_invalid_signature() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let token = JwtToken::parse(raw).unwrap();
        let key = VerificationKey::Hmac(HmacKey::new(b"wrong-secret".to_vec()));
        let verif_opts = VerificationOptions::default();
        let claim_opts = ClaimValidationOptions::default();
        let now = DateTime::from_timestamp(1516239025, 0).unwrap();

        let report = verify_jwt(
            &token,
            JwtAlgorithm::HS256,
            &key,
            &verif_opts,
            &claim_opts,
            now,
        );

        assert!(!report.valid);
        assert_eq!(report.signature.status, SignatureStatus::Invalid);
    }

    #[test]
    fn test_verify_jwt_expired() {
        let key = VerificationKey::Hmac(HmacKey::new(b"your-256-bit-secret".to_vec()));
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let token = JwtToken::parse(raw).unwrap();
        let verif_opts = VerificationOptions::default();
        // Require exp claim which is missing
        let claim_opts = ClaimValidationOptions {
            require_exp: true,
            ..Default::default()
        };
        let now = DateTime::from_timestamp(1516239025, 0).unwrap();

        let report = verify_jwt(
            &token,
            JwtAlgorithm::HS256,
            &key,
            &verif_opts,
            &claim_opts,
            now,
        );

        assert!(!report.valid);
        assert_eq!(report.signature.status, SignatureStatus::Valid);
        assert_eq!(report.claims.status, ClaimCheckStatus::Invalid);
        assert_eq!(report.claims.expiration, ClaimCheckStatus::Missing);
    }
}
