# jwt-debugger

[English](README.md) | [Tiếng Việt](README.vi.md)

[![CI](https://github.com/haiphamngoc-dev/jwt-debugger/actions/workflows/ci.yml/badge.svg)](https://github.com/haiphamngoc-dev/jwt-debugger/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/jwt-debugger.svg)](https://crates.io/crates/jwt-debugger)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust: 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org)

A secure-by-default, lightning-fast developer CLI tool and Rust library to inspect, decode, verify, and debug JSON Web Tokens (JWT / JWS / JWK / JWKS).

Designed for developers, security engineers, DevOps, and automated CI/CD pipelines.

---

## Key Features

- **Secure by Default**:
  - Cryptographic verification is strictly enforced before trusting any claim.
  - Mitigates Algorithm Confusion Attacks (e.g. preventing HMAC verification with RSA public keys).
  - Rejects unsecured tokens (`alg: none`) unless explicitly permitted via `--allow-unsecured`.
  - Enforces HTTPS for remote JWKS endpoints (configurable for local development).
- **Complete Algorithm Support**:
  - **HMAC**: `HS256`, `HS384`, `HS512`
  - **RSA PKCS#1 v1.5**: `RS256`, `RS384`, `RS512`
  - **RSA-PSS**: `PS256`, `PS384`, `PS512`
  - **ECDSA**: `ES256` (P-256), `ES384` (P-384)
  - **EdDSA**: `EdDSA` (Ed25519)
  - **Unsecured**: `none`
- **Deep Inspection & Security Linting**:
  - Structural segment byte sizing and format verification.
  - Temporal calculations: token age, total lifetime, and remaining time until expiration.
  - Automated security warnings: missing `exp`, future `iat`/`nbf`, unusual header types, and long lifetimes.
- **Flexible Key Resolution**:
  - Direct secret strings, secret files, Hex, Base64, and Base64URL encoded secrets.
  - PEM public keys (PKCS#8 SPKI, PKCS#1 RSA, SEC1 EC, and Ed25519).
  - Local JSON Web Key (`JWK`) and Key Set (`JWKS`) files.
  - Remote HTTPS JWKS endpoints with automatic Key ID (`kid`) resolution.
- **UNIX Pipeline & Automation Ready**:
  - Semantic process exit codes (`0`-`7`) for scripting and CI/CD pipelines.
  - Machine-readable `--json` output, compact format `--compact`, and quiet mode `--quiet`.
  - Input tokens from positional argument, `--token`, `--token-file`, or direct `stdin` pipe.
- **Shell Autocompletions**:
  - Native generator for Bash, Zsh, Fish, PowerShell, and Elvish.

---

## Verification Flow Architecture

```mermaid
flowchart TD
    A["Raw JWT Input\n(CLI arg, flag, file, stdin)"] --> B["Parser & Structural Validation\n(3 Base64URL segments)"]
    B --> C{"Command"}

    C -->|"decode"| D["Decode JOSE Header, Payload & Signature"]
    C -->|"inspect"| E["Temporal & Security Analysis\n(Age, Lifetime, Security Warnings)"]
    C -->|"verify"| F["Resolve Verification Key\n(Secret, PEM, JWK, Remote JWKS)"]

    F --> G{"Algorithm Match & Compatibility Check"}
    G -->|Mismatch| H["Reject (Algorithm Confusion Protected)"]
    G -->|Compatible| I["Cryptographic Signature Check"]

    I -->|Valid| J["Validate Registered Claims\n(exp, nbf, iat, iss, aud, sub + leeway)"]
    I -->|Invalid| K["Exit 4: EXIT_SIGNATURE_INVALID"]

    J -->|Passed| L["Exit 0: VERIFICATION SUCCESSFUL"]
    J -->|Failed| M["Exit 5: EXIT_CLAIMS_INVALID"]
```

---

## Installation

### From Crates.io (Recommended)

```bash
cargo install jwt-debugger
```

### From Source

```bash
git clone https://github.com/haiphamngoc-dev/jwt-debugger.git
cd jwt-debugger
cargo build --release
cp target/release/jwt-debugger /usr/local/bin/
```

---

## CLI Usage & Quickstart

```text
Usage: jwt-debugger [OPTIONS] <COMMAND>

Commands:
  decode      Decode and display JWT header, payload, and signature
  inspect     Inspect JWT structure, metadata, standard claims, timing, and security warnings
  verify      Verify JWT signature and validate standard claims
  claims      Display and validate JWT claims with timing analysis
  header      Decode and output only the JWT header
  payload     Decode and output only the JWT payload
  signature   Extract and display JWT signature in various encodings
  jwk         Inspect and verify tokens using JSON Web Keys (JWK / JWKS)
  completion  Generate shell completion script
  help        Print this message or the help of the given subcommand(s)
```

---

### 1. Decoding Tokens (`decode`)

Decode full token segments into formatted, readable output:

```bash
jwt-debugger decode "$TOKEN"
```

Sample Terminal Output:

```text
Header
──────
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload
───────
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}

Signature
─────────
Algorithm:      HS256
Base64URL:      SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Bytes:          32
```

Machine-readable JSON output:

```bash
jwt-debugger decode "$TOKEN" --json
```

---

### 2. Deep Inspection & Security Warnings (`inspect`)

Analyze token structure, timestamps, and detect security vulnerabilities:

```bash
jwt-debugger inspect "$TOKEN" --timezone UTC
```

Sample Terminal Output:

```text
JWT Debugger - Inspect

Structure
─────────
Segments:       3
Format:         JWS Compact Serialization
Size:           172 bytes (header: 27, payload: 57, signature: 32)

Header
──────
Algorithm:      HS256
Type:           JWT

Claims
──────
Subject:        1234567890
Issued At:      2018-01-18 01:30:22 UTC
Expires At:     2026-09-18 15:30:00 UTC

Lifetime
────────
Token lifetime: 8y 243d
Age:            8y 243d
Expires in:     2h 15m

Signature
─────────
Algorithm:      HS256
Signature bytes: 32
Verification:   NOT PERFORMED

Warnings
────────
- LONG_LIFETIME: Token lifetime is unusually long (8y 243d).
```

---

### 3. Verifying Tokens (`verify`)

#### HMAC Secret (HS256, HS384, HS512)

```bash
# Via secret string
jwt-debugger verify "$TOKEN" --alg HS256 --secret "your-256-bit-secret"

# Via secure file (prevents secret exposure in process lists)
jwt-debugger verify "$TOKEN" --alg HS256 --secret-file ./secret.key

# Via Hex, Base64, or Base64URL
jwt-debugger verify "$TOKEN" --alg HS256 --secret-hex "796f75722d736563726574"
jwt-debugger verify "$TOKEN" --alg HS256 --secret-base64 "eW91ci1zZWNyZXQ="
```

#### RSA, ECDSA, and EdDSA PEM Keys

```bash
# RSA (RS256 / PS256) with PEM public key
jwt-debugger verify "$TOKEN" --alg RS256 --public-key ./public_key.pem

# ECDSA (ES256 / ES384) with PEM public key
jwt-debugger verify "$TOKEN" --alg ES256 --public-key ./ec_public.pem

# EdDSA (Ed25519) with PEM public key
jwt-debugger verify "$TOKEN" --alg EdDSA --public-key ./ed25519_public.pem
```

#### Remote JWKS (Auth0, Okta, Keycloak, Firebase, etc.)

```bash
# Automatically selects matching key using the token's header 'kid'
jwt-debugger verify "$TOKEN" \
  --alg RS256 \
  --jwks-url https://auth.example.com/.well-known/jwks.json \
  --issuer https://auth.example.com/ \
  --audience my-api-audience
```

#### Claims & Leeway Validation

```bash
jwt-debugger verify "$TOKEN" \
  --alg HS256 \
  --secret-file ./secret.key \
  --issuer https://issuer.example.com \
  --audience my-service \
  --subject user123 \
  --leeway 30s \
  --require-exp \
  --require-iat
```

---

### 4. Segment Extractors

Extract specific parts of a JWT directly:

```bash
# Extract Header as JSON
jwt-debugger header "$TOKEN" --compact

# Extract Payload as JSON
jwt-debugger payload "$TOKEN"

# Extract Signature in different encodings
jwt-debugger signature "$TOKEN" --hex
jwt-debugger signature "$TOKEN" --base64
jwt-debugger signature "$TOKEN" --base64url
jwt-debugger signature "$TOKEN" --raw > signature.bin
```

---

### 5. JWK & JWKS Operations (`jwk`)

```bash
# Inspect local JWK or JWKS file
jwt-debugger jwk inspect ./jwks.json

# Verify token against a local JWK file
jwt-debugger jwk verify "$TOKEN" --alg HS256 --jwk ./key.json
```

---

### 6. Shell Autocompletion (`completion`)

Generate completion scripts for your shell:

```bash
# Bash
jwt-debugger completion bash > ~/.local/share/bash-completion/completions/jwt-debugger

# Zsh
jwt-debugger completion zsh > ~/.zsh/completion/_jwt-debugger

# Fish
jwt-debugger completion fish > ~/.config/fish/completions/jwt-debugger.fish
```

---

## UNIX Pipeline & Automation Recipes

### Extract claims using `jq`

```bash
echo "$TOKEN" | jwt-debugger payload --json | jq '.user_id'
```

### Validate token in a bash script / CI workflow

```bash
if jwt-debugger verify "$TOKEN" --alg RS256 --public-key ./key.pem --quiet; then
    echo "Authentication successful"
else
    echo "Invalid or expired token"
    exit 1
fi
```

---

## Semantic Process Exit Codes

`jwt-debugger` provides predictable exit codes for robust scripting and automation:

| Exit Code | Name | Description |
| :---: | :--- | :--- |
| **`0`** | `EXIT_SUCCESS` | Command completed successfully; signature and claims are valid. |
| **`1`** | `EXIT_GENERIC_ERROR` | Generic or unexpected runtime error. |
| **`2`** | `EXIT_INVALID_USAGE` | Invalid CLI arguments or conflicting option flags. |
| **`3`** | `EXIT_MALFORMED_JWT` | JWT string is malformed or has invalid segment count. |
| **`4`** | `EXIT_SIGNATURE_INVALID` | Cryptographic signature verification failed. |
| **`5`** | `EXIT_CLAIMS_INVALID` | Claim constraints failed (token expired, issuer/aud mismatch). |
| **`6`** | `EXIT_KEY_ERROR` | Key error (cannot read file, invalid PEM/JWK format). |
| **`7`** | `EXIT_NETWORK_ERROR` | Network failure during remote JWKS fetch. |

---

## Rust SDK Library Usage

`jwt-debugger` is also available as a high-performance Rust library.

Add it to your `Cargo.toml`:

```toml
[dependencies]
jwt-debugger = "0.1"
```

### Example: Verify Token and Validate Claims

```rust
use chrono::Utc;
use std::time::Duration;
use jwt_debugger::{
    JwtToken, JwtAlgorithm, VerificationKey, HmacKey,
    VerificationOptions, ClaimValidationOptions, verify_jwt
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let token = JwtToken::parse(raw)?;

    let key = VerificationKey::Hmac(HmacKey::new(b"your-256-bit-secret".to_vec()));
    let ver_opts = VerificationOptions::default();
    let claim_opts = ClaimValidationOptions {
        subject: Some("1234567890".to_string()),
        leeway: Duration::from_secs(30),
        ..Default::default()
    };

    let report = verify_jwt(
        &token,
        JwtAlgorithm::HS256,
        &key,
        &ver_opts,
        &claim_opts,
        Utc::now(),
    );

    if report.valid {
        println!("JWT is valid! Subject: {:?}", token.claims.sub);
    } else {
        eprintln!("Verification failed: {:?}", report.signature.error);
    }

    Ok(())
}
```

---

## Documentation

For a comprehensive, production-grade guide to JSON Web Tokens and the JOSE ecosystem (available in Vietnamese), explore our [Documentation Series](docs/README.md):

- [Chapter 1: Overview & Architecture (Stateful vs Stateless, JWS vs JWE)](docs/01-tong-quan-va-kien-truc.md)
- [Chapter 2: Structure & Base64URL Encoding](docs/02-cau-truc-va-ma-hoa-base64url.md)
- [Chapter 3: JWA Cryptographic Algorithms (HMAC, RSA, ECDSA, EdDSA)](docs/03-cac-thuat-toan-ky-jwa.md)
- [Chapter 4: JWK & JWKS Standards (OIDC Discovery, Zero-Downtime Key Rotation)](docs/04-tieu-chuan-jwk-va-jwks.md)
- [Chapter 5: Classic Security Vulnerabilities & Defense Mechanisms](docs/05-cac-lo-hong-bao-mat-kinh-dien.md)
- [Chapter 6: Production Best Practices & Architectural Patterns](docs/06-best-practices-va-chuan-trien-khai.md)
- [Chapter 7: Practical Cookbook with jwt-debugger CLI](docs/07-so-tay-thuc-chien-jwt-debugger.md)

---

## Supported Standards & Specifications

- **[RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)**: JSON Web Token (JWT)
- **[RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)**: JSON Web Signature (JWS)
- **[RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)**: JSON Web Key (JWK)
- **[RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)**: JSON Web Algorithms (JWA)
- **[RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037)**: CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE (Ed25519)

---

## License

This project is licensed under the [MIT License](LICENSE).
