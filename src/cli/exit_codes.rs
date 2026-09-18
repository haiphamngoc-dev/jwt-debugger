//! Process exit codes and semantic exit statuses for CLI operations.

use std::process::ExitCode;

/// Process successfully completed (no errors, verification succeeded).
pub const EXIT_SUCCESS: u8 = 0;
/// Unhandled generic error occurred.
pub const EXIT_GENERIC_ERROR: u8 = 1;
/// Invalid CLI arguments or conflicting flags provided.
pub const EXIT_INVALID_USAGE: u8 = 2;
/// JWT string is malformed or cannot be parsed.
pub const EXIT_MALFORMED_JWT: u8 = 3;
/// Cryptographic signature verification failed or signature is invalid.
pub const EXIT_SIGNATURE_INVALID: u8 = 4;
/// Claim validation failed (e.g. expired, future iat, issuer/audience mismatch).
pub const EXIT_CLAIMS_INVALID: u8 = 5;
/// Key error (e.g. failed to read key file, invalid PEM/JWK format, incompatible algorithm).
pub const EXIT_KEY_ERROR: u8 = 6;
/// Network error fetching remote JWKS.
pub const EXIT_NETWORK_ERROR: u8 = 7;

/// Semantic exit statuses produced by CLI subcommand executions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliExit {
    /// Command completed successfully.
    Success,
    /// Generic or unexpected runtime error.
    GenericError,
    /// Invalid usage or option combination.
    InvalidUsage,
    /// Malformed JWT token structure or encoding.
    MalformedJwt,
    /// Cryptographic signature check failed.
    SignatureInvalid,
    /// Claims validation constraints failed.
    ClaimsInvalid,
    /// Cryptographic key resolution or format error.
    KeyError,
    /// Network failure during remote JWKS fetch.
    NetworkError,
}

impl CliExit {
    /// Returns the integer exit code associated with this status.
    pub fn code(&self) -> u8 {
        match self {
            Self::Success => EXIT_SUCCESS,
            Self::GenericError => EXIT_GENERIC_ERROR,
            Self::InvalidUsage => EXIT_INVALID_USAGE,
            Self::MalformedJwt => EXIT_MALFORMED_JWT,
            Self::SignatureInvalid => EXIT_SIGNATURE_INVALID,
            Self::ClaimsInvalid => EXIT_CLAIMS_INVALID,
            Self::KeyError => EXIT_KEY_ERROR,
            Self::NetworkError => EXIT_NETWORK_ERROR,
        }
    }

    /// Converts this status into a standard [`ExitCode`].
    pub fn to_exit_code(self) -> ExitCode {
        ExitCode::from(self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_codes_mapping() {
        assert_eq!(CliExit::Success.code(), EXIT_SUCCESS);
        assert_eq!(CliExit::GenericError.code(), EXIT_GENERIC_ERROR);
        assert_eq!(CliExit::InvalidUsage.code(), EXIT_INVALID_USAGE);
        assert_eq!(CliExit::MalformedJwt.code(), EXIT_MALFORMED_JWT);
        assert_eq!(CliExit::SignatureInvalid.code(), EXIT_SIGNATURE_INVALID);
        assert_eq!(CliExit::ClaimsInvalid.code(), EXIT_CLAIMS_INVALID);
        assert_eq!(CliExit::KeyError.code(), EXIT_KEY_ERROR);
        assert_eq!(CliExit::NetworkError.code(), EXIT_NETWORK_ERROR);
    }
}
