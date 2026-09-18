use assert_cmd::Command;
use predicates::prelude::*;

mod common;
use common::{HS256_TOKEN, JWK_OCT_JSON, JWKS_JSON, create_temp_file};

#[test]
fn test_cli_jwk_inspect_single_key() {
    let jwk_file = create_temp_file(JWK_OCT_JSON);
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("jwk")
        .arg("inspect")
        .arg(jwk_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("JSON Web Key (JWK)"))
        .stdout(predicate::str::contains("Key Type (kty):"))
        .stdout(predicate::str::contains("oct"))
        .stdout(predicate::str::contains("my-hmac-key"));
}

#[test]
fn test_cli_jwk_inspect_jwks() {
    let jwks_file = create_temp_file(JWKS_JSON);
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("jwk")
        .arg("inspect")
        .arg(jwks_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("JSON Web Key Set (JWKS)"))
        .stdout(predicate::str::contains("Total Keys:     2"))
        .stdout(predicate::str::contains("Key #1"))
        .stdout(predicate::str::contains("Key #2"))
        .stdout(predicate::str::contains("P-256"));
}

#[test]
fn test_cli_jwk_inspect_json() {
    let jwks_file = create_temp_file(JWKS_JSON);
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    let assert = cmd
        .arg("jwk")
        .arg("inspect")
        .arg(jwks_file.path())
        .arg("--json")
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["keys"].as_array().unwrap().len(), 2);
}

#[test]
fn test_cli_jwk_verify_success() {
    let jwk_file = create_temp_file(JWK_OCT_JSON);
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("jwk")
        .arg("verify")
        .arg(HS256_TOKEN)
        .arg("--alg")
        .arg("HS256")
        .arg("--jwk")
        .arg(jwk_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "VALID: Signature verified successfully",
        ));
}
