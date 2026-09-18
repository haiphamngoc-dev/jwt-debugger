//! Domain error types for JWT parsing, cryptographic operations, claim validation, and JWKS retrieval.

use thiserror::Error;

/// Errors that can occur when parsing or inspecting a JSON Web Token (JWT).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JwtError {
    /// The token input string is empty or contains only whitespace.
    #[error("Token string is empty")]
    EmptyToken,

    /// The token exceeds the maximum supported size limit.
    #[error("JWT exceeds maximum supported size of {0} bytes")]
    TokenTooLarge(usize),

    /// A JSON Web Encryption (JWE) token with 5 segments was passed where a JWS was expected.
    #[error(
        "JWE tokens are not supported. Expected a signed JWT/JWS with 3 segments, found 5 segments."
    )]
    JweNotSupported,

    /// The token does not have exactly 3 dot-separated segments (header, payload, signature).
    #[error("Invalid JWT segment count: expected 3 segments (header.payload.signature), found {0}")]
    InvalidSegmentCount(usize),

    /// Base64URL decoding failed for the JOSE header segment.
    #[error("Invalid Base64URL in header: {0}")]
    InvalidHeaderEncoding(String),

    /// Base64URL decoding failed for the payload segment.
    #[error("Invalid Base64URL in payload: {0}")]
    InvalidPayloadEncoding(String),

    /// Base64URL decoding failed for the signature segment.
    #[error("Invalid Base64URL in signature: {0}")]
    InvalidSignatureEncoding(String),

    /// Header segment bytes do not form valid UTF-8.
    #[error("Invalid UTF-8 in JWT header: {0}")]
    InvalidHeaderUtf8(String),

    /// Payload segment bytes do not form valid UTF-8.
    #[error("Invalid UTF-8 in JWT payload: {0}")]
    InvalidPayloadUtf8(String),

    /// Header JSON parsing failed.
    #[error("Invalid JSON in JWT header: {0}")]
    InvalidHeaderJson(String),

    /// Payload JSON parsing failed.
    #[error("Invalid JSON in JWT payload: {0}")]
    InvalidPayloadJson(String),

    /// The JOSE header is missing the required `alg` claim.
    #[error("JWT header is missing 'alg' claim")]
    MissingAlgorithm,

    /// The algorithm specified in the JOSE header is unknown or not supported.
    #[error("Unsupported or unknown algorithm: '{0}'")]
    UnsupportedAlgorithm(String),
}

/// Errors that can occur during cryptographic key loading and signature verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// The provided key or algorithm does not match the token's `alg` header.
    #[error("Algorithm mismatch: expected '{expected}', but token header specified '{token_alg}'")]
    AlgorithmMismatch {
        /// Expected algorithm based on the verification key or CLI argument.
        expected: String,
        /// Algorithm specified in the token's header.
        token_alg: String,
    },

    /// The supplied key type is not compatible with the specified algorithm.
    #[error(
        "Key type mismatch: algorithm '{algorithm}' is not compatible with key type '{key_type}'"
    )]
    KeyTypeMismatch {
        /// The algorithm requiring a key.
        algorithm: String,
        /// The type of key provided.
        key_type: String,
    },

    /// The symmetric HMAC secret could not be parsed or decoded.
    #[error("Invalid secret format: {0}")]
    InvalidSecret(String),

    /// The PEM encoded public key could not be decoded.
    #[error("Invalid PEM public key: {0}")]
    InvalidPem(String),

    /// The RSA public key is malformed or invalid.
    #[error("Invalid RSA public key: {0}")]
    InvalidRsaKey(String),

    /// The ECDSA public key is malformed or invalid.
    #[error("Invalid ECDSA public key: {0}")]
    InvalidEcKey(String),

    /// The Ed25519 public key is malformed or invalid.
    #[error("Invalid Ed25519 public key: {0}")]
    InvalidEdKey(String),

    /// The elliptic curve of the key does not match the required curve for the algorithm.
    #[error(
        "Incompatible curve: algorithm '{algorithm}' requires curve '{expected_curve}', found '{actual_curve}'"
    )]
    CurveMismatch {
        /// The algorithm name.
        algorithm: String,
        /// The required elliptic curve.
        expected_curve: String,
        /// The actual elliptic curve found in the key.
        actual_curve: String,
    },

    /// Cryptographic signature verification failed.
    #[error("Signature verification failed: cryptographic signature does not match")]
    InvalidSignature,

    /// Unsecured tokens (`alg=none`) were rejected because `--allow-unsecured` was not enabled.
    #[error("Unsecured JWT (alg=none) is not accepted for verification without --allow-unsecured")]
    UnsecuredNotAllowed,

    /// The requested cryptographic algorithm is unsupported.
    #[error("Unsupported algorithm: '{0}'")]
    UnsupportedAlgorithm(String),
}

/// Errors that can occur when validating registered or standard JWT claims.
#[derive(Debug, Error, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub enum ClaimValidationError {
    /// The token has expired (`exp` claim is in the past).
    #[error("Token expired at {expired_at} ({relative})")]
    Expired {
        /// Formatted expiration date string.
        expired_at: String,
        /// Relative time string (e.g. `"15m ago"`).
        relative: String,
    },

    /// The token is not valid yet (`nbf` claim is in the future).
    #[error("Token is not valid yet; not before (nbf) is {nbf} ({relative})")]
    NotYetValid {
        /// Formatted not-before date string.
        nbf: String,
        /// Relative time string (e.g. `"in 5m"`).
        relative: String,
    },

    /// The token's issued-at time (`iat`) is in the future.
    #[error("Token was issued in the future; issued at (iat) is {iat} ({relative})")]
    FutureIssuedAt {
        /// Formatted issued-at date string.
        iat: String,
        /// Relative time string (e.g. `"in 1m"`).
        relative: String,
    },

    /// The issuer (`iss`) does not match the expected issuer.
    #[error("Issuer mismatch: expected '{expected}', found '{actual}'")]
    IssuerMismatch {
        /// Expected issuer identifier.
        expected: String,
        /// Actual issuer claim in the token.
        actual: String,
    },

    /// The audience (`aud`) does not match the expected audience.
    #[error("Audience mismatch: expected '{expected}', found '{actual}'")]
    AudienceMismatch {
        /// Expected audience identifier.
        expected: String,
        /// Actual audience claim in the token.
        actual: String,
    },

    /// The subject (`sub`) does not match the expected subject.
    #[error("Subject mismatch: expected '{expected}', found '{actual}'")]
    SubjectMismatch {
        /// Expected subject identifier.
        expected: String,
        /// Actual subject claim in the token.
        actual: String,
    },

    /// A required claim was not present in the payload.
    #[error("Missing required claim '{0}'")]
    MissingRequiredClaim(String),

    /// A NumericDate claim could not be parsed as a valid Unix timestamp.
    #[error(
        "Invalid NumericDate claim '{claim}': value {value} cannot be parsed as Unix timestamp"
    )]
    InvalidNumericDate {
        /// Claim name (e.g. `"exp"`, `"iat"`).
        claim: String,
        /// Raw value that failed parsing.
        value: String,
    },
}

/// Errors that can occur when fetching, parsing, or resolving keys from a JWKS endpoint.
#[derive(Debug, Error)]
pub enum JwksError {
    /// Network connection or transport error.
    #[error("Network error fetching JWKS: {0}")]
    Network(String),

    /// HTTP request timed out.
    #[error("HTTP request timed out after {0}")]
    Timeout(String),

    /// Non-2xx HTTP status code returned by server.
    #[error("HTTP request failed with status code {0}")]
    HttpStatus(u16),

    /// Response payload exceeded the maximum allowed size limit.
    #[error("JWKS response exceeds maximum allowed size of {0} bytes")]
    ResponseTooLarge(usize),

    /// Plain HTTP was requested without `--allow-insecure-http`.
    #[error("Insecure HTTP URL '{0}' is not allowed unless --allow-insecure-http is specified")]
    InsecureHttpNotAllowed(String),

    /// JWKS JSON response could not be parsed.
    #[error("Invalid JWKS JSON: {0}")]
    InvalidJson(String),

    /// No matching key was found for the token's `kid`.
    #[error("No matching JWK found for kid '{0}'")]
    KeyNotFound(String),

    /// JWKS contains multiple keys and the token header does not specify `kid`.
    #[error(
        "Cannot select a verification key: JWT header does not contain \"kid\" and JWKS contains multiple compatible keys"
    )]
    AmbiguousKey,

    /// No keys compatible with the token algorithm were found.
    #[error("No compatible verification keys found in JWKS for algorithm '{0}'")]
    NoCompatibleKey(String),

    /// The matched key in the JWKS cannot be used for verification.
    #[error("JWK key '{kid}' is not compatible: {reason}")]
    IncompatibleKey {
        /// Key ID.
        kid: String,
        /// Reason for incompatibility.
        reason: String,
    },
}
