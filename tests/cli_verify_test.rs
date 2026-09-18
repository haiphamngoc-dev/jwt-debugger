use assert_cmd::Command;
use predicates::prelude::*;

mod common;
use common::{HS256_SECRET, HS256_TOKEN, UNSECURED_TOKEN, create_temp_file};

#[test]
fn test_cli_verify_hmac_secret_flag() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("verify")
        .arg(HS256_TOKEN)
        .arg("--alg")
        .arg("HS256")
        .arg("--secret")
        .arg(HS256_SECRET)
        .assert()
        .success()
        .stdout(predicate::str::contains("VERIFICATION SUCCESSFUL"))
        .stdout(predicate::str::contains("VALID"));
}

#[test]
fn test_cli_verify_hmac_secret_file() {
    let secret_file = create_temp_file(HS256_SECRET);
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("verify")
        .arg(HS256_TOKEN)
        .arg("--alg")
        .arg("HS256")
        .arg("--secret-file")
        .arg(secret_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("VERIFICATION SUCCESSFUL"));
}

#[test]
fn test_cli_verify_hmac_secret_hex() {
    // "your-256-bit-secret" in hex:
    let hex_secret = hex::encode(HS256_SECRET);
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("verify")
        .arg(HS256_TOKEN)
        .arg("--alg")
        .arg("HS256")
        .arg("--secret-hex")
        .arg(hex_secret)
        .assert()
        .success()
        .stdout(predicate::str::contains("VERIFICATION SUCCESSFUL"));
}

#[test]
fn test_cli_verify_hmac_secret_base64() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    let b64_secret = STANDARD.encode(HS256_SECRET);

    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("verify")
        .arg(HS256_TOKEN)
        .arg("--alg")
        .arg("HS256")
        .arg("--secret-base64")
        .arg(b64_secret)
        .assert()
        .success()
        .stdout(predicate::str::contains("VERIFICATION SUCCESSFUL"));
}

#[test]
fn test_cli_verify_invalid_signature_exit_code() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("verify")
        .arg(HS256_TOKEN)
        .arg("--alg")
        .arg("HS256")
        .arg("--secret")
        .arg("wrong-secret-value")
        .assert()
        .code(4) // EXIT_SIGNATURE_INVALID
        .stdout(predicate::str::contains("VERIFICATION FAILED"));
}

#[test]
fn test_cli_verify_unsecured_token_rejected_by_default() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("verify")
        .arg(UNSECURED_TOKEN)
        .arg("--alg")
        .arg("none")
        .assert()
        .code(2) // EXIT_INVALID_USAGE
        .stderr(predicate::str::contains("Unsecured JWT (alg=none) is not accepted"));
}

#[test]
fn test_cli_verify_unsecured_token_accepted_with_flag() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("verify")
        .arg(UNSECURED_TOKEN)
        .arg("--alg")
        .arg("none")
        .arg("--allow-unsecured")
        .assert()
        .success()
        .stdout(predicate::str::contains("VERIFICATION SUCCESSFUL"));
}

#[test]
fn test_cli_verify_claims_matching_and_mismatch() {
    // Valid subject match
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("verify")
        .arg(HS256_TOKEN)
        .arg("--alg")
        .arg("HS256")
        .arg("--secret")
        .arg(HS256_SECRET)
        .arg("--subject")
        .arg("1234567890")
        .assert()
        .success()
        .stdout(predicate::str::contains("VERIFICATION SUCCESSFUL"));

    // Claims subject mismatch
    let mut cmd_mismatch = Command::cargo_bin("jwt-debugger").unwrap();
    cmd_mismatch
        .arg("verify")
        .arg(HS256_TOKEN)
        .arg("--alg")
        .arg("HS256")
        .arg("--secret")
        .arg(HS256_SECRET)
        .arg("--subject")
        .arg("wrong-user-id")
        .assert()
        .code(5) // EXIT_CLAIMS_INVALID
        .stdout(predicate::str::contains("VERIFICATION FAILED"));
}

#[test]
fn test_cli_verify_require_exp_failure() {
    // HS256_TOKEN does not have exp claim
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("verify")
        .arg(HS256_TOKEN)
        .arg("--alg")
        .arg("HS256")
        .arg("--secret")
        .arg(HS256_SECRET)
        .arg("--require-exp")
        .assert()
        .code(5) // EXIT_CLAIMS_INVALID
        .stdout(predicate::str::contains("VERIFICATION FAILED"))
        .stdout(predicate::str::contains("MISSING"));
}

#[test]
fn test_cli_verify_missing_key_argument() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("verify")
        .arg(HS256_TOKEN)
        .arg("--alg")
        .arg("HS256")
        .assert()
        .code(2) // EXIT_INVALID_USAGE
        .stderr(predicate::str::contains("No verification key provided"));
}

#[test]
fn test_cli_verify_invalid_pem_key_error() {
    let bad_pem = create_temp_file("not-a-valid-pem-content");
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("verify")
        .arg(HS256_TOKEN)
        .arg("--alg")
        .arg("RS256")
        .arg("--public-key")
        .arg(bad_pem.path())
        .assert()
        .code(6) // EXIT_KEY_ERROR
        .stderr(predicate::str::contains("Key Error"));
}
