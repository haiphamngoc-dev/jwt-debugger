//! Common test helpers, fixtures, and sample tokens for integration testing.

#![allow(dead_code)]

use std::io::Write;
use tempfile::NamedTempFile;

/// Standard RFC 7519 / RFC 7515 test token signed with HMAC-SHA256 (`secret`: `"your-256-bit-secret"`).
pub const HS256_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
pub const HS256_SECRET: &str = "your-256-bit-secret";

/// Unsecured token (`alg: "none"`).
pub const UNSECURED_TOKEN: &str =
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.";

/// Token with claims for issuer, audience, subject, exp, iat, nbf.
/// Header: `{"alg":"HS256","typ":"JWT"}`
/// Payload: `{"sub":"user123","iss":"https://auth.example.com","aud":"api.example.com","iat":1516239022,"exp":2500000000,"nbf":1516239022}`
/// Secret: `"test-secret"`
pub const HS256_FULL_CLAIMS_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhcGkuZXhhbXBsZS5jb20iLCJleHAiOjI1MDAwMDAwMDAsImlhdCI6MTUxNjIzOTAyMiwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tIiwibmJmIjoxNTE2MjM5MDIyLCJzdWIiOiJ1c2VyMTIzIn0.fC6a836Z0xYlQ86k1oNf3W1-uTf231qjYv2sV0m4Nq0";
pub const HS256_FULL_CLAIMS_SECRET: &str = "test-secret";

/// Sample RSA 2048-bit Public Key in PKCS#8 PEM format.
pub const RSA_PUBLIC_KEY_PKCS8_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA10qDfnqL5wB5f5YpZkZk\n\
QzWfU7Fk1gq1Xw6O1vY7X6cZ6o8Q8v8dF7sE8a3w1B8P8h1W1x7Z7Y8e1c6b1a2\n\
3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4\n\
i5j6k7l8m9n0o1p2q3r4s5t6u7v8w9x0y1z2a3b4c5d6e7f8g9h0i1j2k3l4m5n\n\
6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c1d2e3f4g5h6i7j8k9l0m1n2o3p4q5r6s7\n\
t8u9v0w1x2y3z4a5b6c7d8e9f0==\n\
-----END PUBLIC KEY-----\n";

/// Sample RSA 2048-bit Public Key in PKCS#1 PEM format.
pub const RSA_PUBLIC_KEY_PKCS1_PEM: &str = "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEAy9WlHwJmC8p5Yd5yPq6J5K9L8M7N6O5P4Q3R2S1T0U9V8W7X6Y5Z\n\
4a3b2c1d0e9f8g7h6i5j4k3l2m1n0o9p8q7r6s5t4u3v2w1x0y9z8a7b6c5d4e3f\n\
2g1h0i9j8k7l6m5n4o3p2q1r0s9t8u7v6w5x4y3z2a1b0c9d8e7f6g5h4i3j2k1l\n\
0m9n8o7p6q5r4s3t2u1v0w9x8y7z6a5b4c3d2e1f0g9h8i7j6k5l4m3n2o1p0q9r\n\
8s7t6u5v4w3x2y1z0a9b8c7d6e5f4g3h2i1j0k9l8m7n6o5p4q3r2s1t0u9v8w7x\n\
6y5z4wIDAQAB\n\
-----END RSA PUBLIC KEY-----\n";

/// Sample ECDSA P-256 Public Key in SEC1 / PKCS#8 SPKI PEM format.
pub const EC_P256_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf2p7NqH7yP2Yd1mP4a5Z6x7c8v9b\n\
0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f\n\
2g==\n\
-----END PUBLIC KEY-----\n";

/// Sample JWK for HMAC key.
pub const JWK_OCT_JSON: &str = r#"{
  "kty": "oct",
  "k": "eW91ci0yNTYtYml0LXNlY3JldA",
  "alg": "HS256",
  "kid": "my-hmac-key",
  "use": "sig"
}"#;

/// Sample JWKS JSON containing an oct key and an EC key.
pub const JWKS_JSON: &str = r#"{
  "keys": [
    {
      "kty": "oct",
      "k": "eW91ci0yNTYtYml0LXNlY3JldA",
      "alg": "HS256",
      "kid": "key-1",
      "use": "sig"
    },
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "f83OJ3D2xFMTbKEBaGiz-3wYH1509-5Zrx636OxVTzk",
      "y": "x_daQauqmbgUZb4gYIf9DaPSCjjyJxJxAgb498vOi_0",
      "alg": "ES256",
      "kid": "key-2",
      "use": "sig"
    }
  ]
}"#;

/// Creates a temporary file with the provided text content.
pub fn create_temp_file(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("Failed to create temp file");
    file.write_all(content.as_bytes())
        .expect("Failed to write to temp file");
    file.flush().expect("Failed to flush temp file");
    file
}
