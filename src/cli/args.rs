//! CLI argument definitions, command structures, and input resolution.

use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

use super::formatting::ColorChoice;
use crate::infrastructure::filesystem::read_file_to_string;
use crate::infrastructure::stdin::{is_stdin_terminal, read_stdin};

/// Top-level CLI command-line parser definition.
#[derive(Parser, Debug)]
#[command(
    name = "jwt-debugger",
    author = "jwt-debugger contributors",
    version,
    about = "A secure-by-default developer tool to inspect, decode, verify, and debug JSON Web Tokens",
    after_help = "EXAMPLES:\n  \
      Decode a token:\n    \
        jwt-debugger decode \"$TOKEN\"\n\n  \
      Inspect token structure, timing, and security warnings:\n    \
        jwt-debugger inspect \"$TOKEN\" --timezone UTC\n\n  \
      Verify HMAC token:\n    \
        jwt-debugger verify \"$TOKEN\" --alg HS256 --secret-file ./secret.key\n\n  \
      Verify RSA token with PEM public key:\n    \
        jwt-debugger verify \"$TOKEN\" --alg RS256 --public-key ./public.pem --issuer https://auth.example.com\n\n  \
      Verify token using Remote JWKS:\n    \
        jwt-debugger verify \"$TOKEN\" --alg RS256 --jwks-url https://example.com/.well-known/jwks.json\n\n  \
      Pipeline from stdin:\n    \
        echo \"$TOKEN\" | jwt-debugger payload --json | jq .sub"
)]
pub struct Cli {
    /// Color output preference.
    #[arg(
        long,
        global = true,
        default_value = "auto",
        help = "Color output control"
    )]
    pub color: ColorChoice,

    /// Suppress output on success (useful for scripts and pipelines).
    #[arg(
        short,
        long,
        global = true,
        help = "Do not print output on success (useful for scripting)"
    )]
    pub quiet: bool,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Generic options for providing a JWT token to subcommands.
#[derive(Args, Debug, Clone, Default)]
pub struct TokenInputArgs {
    /// JWT string provided as a positional argument.
    #[arg(value_name = "TOKEN", help = "JWT string (positional argument)")]
    pub token_arg: Option<String>,

    /// JWT string provided via `--token` flag.
    #[arg(long, help = "JWT string passed via flag")]
    pub token: Option<String>,

    /// Path to a file containing the JWT string.
    #[arg(long, value_name = "PATH", help = "File containing the JWT")]
    pub token_file: Option<PathBuf>,

    /// Read the JWT string explicitly from standard input.
    #[arg(long, help = "Explicitly read JWT from standard input")]
    pub stdin: bool,
}

impl TokenInputArgs {
    /// Resolves the raw JWT token string from the provided arguments, file, or standard input.
    ///
    /// # Errors
    ///
    /// Returns an error if multiple conflicting input sources are provided, if reading from file or stdin fails,
    /// or if no token input was provided.
    pub fn resolve_token(&self) -> anyhow::Result<String> {
        let mut sources_count = 0;
        if self.token_arg.is_some() {
            sources_count += 1;
        }
        if self.token.is_some() {
            sources_count += 1;
        }
        if self.token_file.is_some() {
            sources_count += 1;
        }
        if self.stdin {
            sources_count += 1;
        }

        if sources_count > 1 {
            anyhow::bail!(
                "Conflicting token input options. Please provide token via positional argument, --token, --token-file, or --stdin, but not multiple simultaneously."
            );
        }

        if let Some(ref t) = self.token_arg {
            return Ok(t.clone());
        }

        if let Some(ref t) = self.token {
            return Ok(t.clone());
        }

        if let Some(ref path) = self.token_file {
            let content = read_file_to_string(path)?;
            return Ok(content.trim().to_string());
        }

        if self.stdin {
            return read_stdin();
        }

        // Auto fallback to stdin if not interactive terminal
        if !is_stdin_terminal() {
            return read_stdin();
        }

        anyhow::bail!(
            "No JWT token provided. Provide token as argument, via --token, --token-file, or pipe into stdin."
        );
    }
}

/// Supported subcommands for `jwt-debugger`.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Decode and display JWT header, payload, and signature.
    #[command(about = "Decode and display JWT header, payload, and signature")]
    Decode(DecodeArgs),

    /// Inspect JWT structure, metadata, standard claims, timing, and security warnings.
    #[command(
        about = "Inspect JWT structure, metadata, standard claims, timing, and security warnings"
    )]
    Inspect(InspectArgs),

    /// Verify JWT signature and validate standard claims.
    #[command(about = "Verify JWT signature and validate standard claims")]
    Verify(Box<VerifyArgs>),

    /// Display and validate JWT claims with timing analysis.
    #[command(about = "Display and validate JWT claims with timing analysis")]
    Claims(ClaimsArgs),

    /// Decode and output only the JWT header.
    #[command(about = "Decode and output only the JWT header")]
    Header(HeaderArgs),

    /// Decode and output only the JWT payload.
    #[command(about = "Decode and output only the JWT payload")]
    Payload(PayloadArgs),

    /// Extract and display JWT signature in various encodings.
    #[command(about = "Extract and display JWT signature in various encodings")]
    Signature(SignatureArgs),

    /// Inspect and verify tokens using JSON Web Keys (JWK / JWKS).
    #[command(about = "Inspect and verify tokens using JSON Web Keys (JWK / JWKS)")]
    Jwk(JwkCommand),

    /// Generate shell completion script.
    #[command(about = "Generate shell completion script")]
    Completion(CompletionArgs),
}

/// Arguments for `decode` subcommand.
#[derive(Args, Debug)]
pub struct DecodeArgs {
    /// Token input source options.
    #[command(flatten)]
    pub input: TokenInputArgs,

    /// Pretty-print JSON objects (default).
    #[arg(
        long,
        conflicts_with = "compact",
        help = "Pretty-print JSON objects (default)"
    )]
    pub pretty: bool,

    /// Output compact JSON objects.
    #[arg(long, conflicts_with = "pretty", help = "Compact JSON objects")]
    pub compact: bool,

    /// Output complete decoded report in machine-readable JSON format.
    #[arg(long, help = "Machine-readable JSON output")]
    pub json: bool,
}

/// Arguments for `inspect` subcommand.
#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Token input source options.
    #[command(flatten)]
    pub input: TokenInputArgs,

    /// Timezone preference for formatted timestamps (`UTC`, `local`, or IANA name).
    #[arg(
        long,
        default_value = "local",
        help = "Timezone for timestamps (UTC, local, or IANA name like 'Asia/Ho_Chi_Minh')"
    )]
    pub timezone: String,

    /// Output complete inspection report in machine-readable JSON format.
    #[arg(long, help = "Machine-readable JSON output")]
    pub json: bool,
}

/// Arguments for `verify` subcommand.
#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Token input source options.
    #[command(flatten)]
    pub input: TokenInputArgs,

    /// Expected cryptographic algorithm (e.g. `HS256`, `RS256`, `ES256`, `EdDSA`, `none`).
    #[arg(
        short = 'a',
        long,
        required = true,
        help = "Expected signing algorithm (e.g., HS256, RS256, ES256, EdDSA, none)"
    )]
    pub alg: String,

    // Symmetric key inputs
    /// HMAC secret string passed directly on CLI.
    #[arg(
        long,
        conflicts_with_all = &["secret_file", "secret_hex", "secret_base64", "secret_base64url", "public_key", "jwk", "jwks", "jwks_url"],
        help = "HMAC secret string (Warning: passing secret on CLI may appear in process lists/shell history; consider --secret-file)"
    )]
    pub secret: Option<String>,

    /// Path to file containing HMAC secret.
    #[arg(
        long,
        conflicts_with_all = &["secret", "secret_hex", "secret_base64", "secret_base64url", "public_key", "jwk", "jwks", "jwks_url"],
        help = "Path to file containing HMAC secret"
    )]
    pub secret_file: Option<PathBuf>,

    /// Hex-encoded HMAC secret string.
    #[arg(
        long,
        conflicts_with_all = &["secret", "secret_file", "secret_base64", "secret_base64url", "public_key", "jwk", "jwks", "jwks_url"],
        help = "Hex-encoded HMAC secret"
    )]
    pub secret_hex: Option<String>,

    /// Base64-encoded HMAC secret string.
    #[arg(
        long,
        conflicts_with_all = &["secret", "secret_file", "secret_hex", "secret_base64url", "public_key", "jwk", "jwks", "jwks_url"],
        help = "Base64-encoded HMAC secret"
    )]
    pub secret_base64: Option<String>,

    /// Base64URL-encoded HMAC secret string.
    #[arg(
        long,
        conflicts_with_all = &["secret", "secret_file", "secret_hex", "secret_base64", "public_key", "jwk", "jwks", "jwks_url"],
        help = "Base64URL-encoded HMAC secret"
    )]
    pub secret_base64url: Option<String>,

    // Asymmetric key inputs
    /// Path to PEM public key file (PKCS#8 SPKI, PKCS#1 RSA, SEC1 EC, or Ed25519).
    #[arg(
        long,
        conflicts_with_all = &["secret", "secret_file", "secret_hex", "secret_base64", "secret_base64url", "jwk", "jwks", "jwks_url"],
        help = "Path to PEM public key (PKCS#8 SPKI, PKCS#1 RSA, SEC1 EC, or Ed25519)"
    )]
    pub public_key: Option<PathBuf>,

    /// Path to local JWK JSON file.
    #[arg(
        long,
        conflicts_with_all = &["secret", "secret_file", "secret_hex", "secret_base64", "secret_base64url", "public_key", "jwks", "jwks_url"],
        help = "Path to local JWK JSON file"
    )]
    pub jwk: Option<PathBuf>,

    /// Path to local JWKS JSON file.
    #[arg(
        long,
        conflicts_with_all = &["secret", "secret_file", "secret_hex", "secret_base64", "secret_base64url", "public_key", "jwk", "jwks_url"],
        help = "Path to local JWKS JSON file"
    )]
    pub jwks: Option<PathBuf>,

    /// URL to remote JWKS endpoint (HTTPS required by default).
    #[arg(
        long,
        conflicts_with_all = &["secret", "secret_file", "secret_hex", "secret_base64", "secret_base64url", "public_key", "jwk", "jwks"],
        help = "URL to remote JWKS endpoint (HTTPS required by default)"
    )]
    pub jwks_url: Option<String>,

    // Claims validation
    /// Expected issuer claim (`iss`).
    #[arg(long, help = "Expected issuer ('iss')")]
    pub issuer: Option<String>,

    /// Expected audience claim (`aud`).
    #[arg(long, help = "Expected audience ('aud')")]
    pub audience: Option<String>,

    /// Expected subject claim (`sub`).
    #[arg(long, help = "Expected subject ('sub')")]
    pub subject: Option<String>,

    /// Allowed clock skew / leeway duration (e.g. `30s`, `2m`).
    #[arg(
        long,
        default_value = "0s",
        help = "Clock skew / leeway duration (e.g., '30s', '2m', '120s')"
    )]
    pub leeway: String,

    /// Require the `exp` claim to be present in the token.
    #[arg(long, help = "Require 'exp' claim to be present in token")]
    pub require_exp: bool,

    /// Require the `iat` claim to be present in the token.
    #[arg(long, help = "Require 'iat' claim to be present in token")]
    pub require_iat: bool,

    /// Require the `nbf` claim to be present in the token.
    #[arg(long, help = "Require 'nbf' claim to be present in token")]
    pub require_nbf: bool,

    // Security overrides
    /// Explicitly allow verification of unsecured tokens (`alg=none`).
    #[arg(
        long,
        help = "Explicitly allow verification of unsecured tokens (alg=none). Note: this does not perform cryptographic verification."
    )]
    pub allow_unsecured: bool,

    /// Timeout for remote JWKS HTTP requests (e.g. `5s`, `10s`).
    #[arg(
        long,
        default_value = "5s",
        help = "Timeout for remote JWKS HTTP requests (e.g., '5s', '10s')"
    )]
    pub timeout: String,

    /// Allow plaintext HTTP for remote JWKS fetching (Insecure).
    #[arg(
        long,
        help = "Allow plaintext HTTP for remote JWKS fetching (Insecure, not recommended)"
    )]
    pub allow_insecure_http: bool,

    /// Output verification report in machine-readable JSON format.
    #[arg(long, help = "Machine-readable JSON output")]
    pub json: bool,
}

/// Arguments for `claims` subcommand.
#[derive(Args, Debug)]
pub struct ClaimsArgs {
    /// Token input source options.
    #[command(flatten)]
    pub input: TokenInputArgs,

    /// Timezone preference for formatted timestamps.
    #[arg(
        long,
        default_value = "local",
        help = "Timezone for timestamps (UTC, local, or IANA name)"
    )]
    pub timezone: String,

    /// Output claims analysis in machine-readable JSON format.
    #[arg(long, help = "Machine-readable JSON output")]
    pub json: bool,
}

/// Arguments for `header` subcommand.
#[derive(Args, Debug)]
pub struct HeaderArgs {
    /// Token input source options.
    #[command(flatten)]
    pub input: TokenInputArgs,

    /// Pretty-print JSON (default).
    #[arg(long, conflicts_with = "compact", help = "Pretty-print JSON (default)")]
    pub pretty: bool,

    /// Output compact JSON.
    #[arg(long, conflicts_with = "pretty", help = "Compact JSON")]
    pub compact: bool,

    /// Output in machine-readable JSON format.
    #[arg(long, help = "Machine-readable JSON output")]
    pub json: bool,
}

/// Arguments for `payload` subcommand.
#[derive(Args, Debug)]
pub struct PayloadArgs {
    /// Token input source options.
    #[command(flatten)]
    pub input: TokenInputArgs,

    /// Pretty-print JSON (default).
    #[arg(long, conflicts_with = "compact", help = "Pretty-print JSON (default)")]
    pub pretty: bool,

    /// Output compact JSON.
    #[arg(long, conflicts_with = "pretty", help = "Compact JSON")]
    pub compact: bool,

    /// Output in machine-readable JSON format.
    #[arg(long, help = "Machine-readable JSON output")]
    pub json: bool,
}

/// Arguments for `signature` subcommand.
#[derive(Args, Debug)]
pub struct SignatureArgs {
    /// Token input source options.
    #[command(flatten)]
    pub input: TokenInputArgs,

    /// Output raw binary signature bytes directly to stdout.
    #[arg(
        long,
        conflicts_with_all = &["hex", "base64", "base64url", "json"],
        help = "Output raw signature bytes directly to stdout"
    )]
    pub raw: bool,

    /// Output signature formatted as hexadecimal string.
    #[arg(
        long,
        conflicts_with_all = &["raw", "base64", "base64url", "json"],
        help = "Output signature as hex string"
    )]
    pub hex: bool,

    /// Output signature formatted as standard Base64 string.
    #[arg(
        long,
        conflicts_with_all = &["raw", "hex", "base64url", "json"],
        help = "Output signature as standard Base64 string"
    )]
    pub base64: bool,

    /// Output signature formatted as Base64URL string.
    #[arg(
        long,
        conflicts_with_all = &["raw", "hex", "base64", "json"],
        help = "Output signature as Base64URL string"
    )]
    pub base64url: bool,

    /// Output signature details in machine-readable JSON format.
    #[arg(
        long,
        conflicts_with_all = &["raw", "hex", "base64", "base64url"],
        help = "Machine-readable JSON output"
    )]
    pub json: bool,
}

/// Arguments for `jwk` command and subcommands.
#[derive(Args, Debug)]
pub struct JwkCommand {
    /// Subcommand for JWK operations.
    #[command(subcommand)]
    pub subcommand: JwkSubcommands,
}

/// Subcommands available under `jwk`.
#[derive(Subcommand, Debug)]
pub enum JwkSubcommands {
    /// Inspect a local JWK or JWKS JSON file.
    #[command(about = "Inspect a local JWK or JWKS JSON file")]
    Inspect {
        /// Path to JWK or JWKS JSON file.
        #[arg(value_name = "FILE", help = "Path to JWK or JWKS JSON file")]
        file: PathBuf,

        /// Output in machine-readable JSON format.
        #[arg(long, help = "Machine-readable JSON output")]
        json: bool,
    },

    /// Verify a JWT signature using a local JWK file.
    #[command(about = "Verify a JWT signature using a local JWK file")]
    Verify {
        /// Token input source options.
        #[command(flatten)]
        input: TokenInputArgs,

        /// Expected signing algorithm.
        #[arg(
            short = 'a',
            long,
            required = true,
            help = "Expected signing algorithm"
        )]
        alg: String,

        /// Path to JWK JSON file.
        #[arg(long, required = true, help = "Path to JWK JSON file")]
        jwk: PathBuf,

        /// Output verification result in machine-readable JSON format.
        #[arg(long, help = "Machine-readable JSON output")]
        json: bool,
    },
}

/// Arguments for `completion` subcommand.
#[derive(Args, Debug)]
pub struct CompletionArgs {
    /// Target shell for shell completion script generation.
    #[arg(value_enum, help = "Shell type")]
    pub shell: Shell,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_input_args_resolve() {
        let input = TokenInputArgs {
            token_arg: Some("abc.def.ghi".to_string()),
            ..Default::default()
        };
        assert_eq!(input.resolve_token().unwrap(), "abc.def.ghi");

        let input_flag = TokenInputArgs {
            token: Some("123.456.789".to_string()),
            ..Default::default()
        };
        assert_eq!(input_flag.resolve_token().unwrap(), "123.456.789");

        let input_conflict = TokenInputArgs {
            token_arg: Some("a".to_string()),
            token: Some("b".to_string()),
            ..Default::default()
        };
        assert!(input_conflict.resolve_token().is_err());
    }

    #[test]
    fn test_cli_parsing_decode() {
        let args = [
            "jwt-debugger",
            "decode",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        match cli.command {
            Commands::Decode(decode_args) => {
                assert_eq!(
                    decode_args.input.token_arg.as_deref(),
                    Some("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig")
                );
            }
            _ => panic!("Expected Commands::Decode"),
        }
    }
}
