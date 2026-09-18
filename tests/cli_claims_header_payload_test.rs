use assert_cmd::Command;
use predicates::prelude::*;

mod common;
use common::HS256_TOKEN;

#[test]
fn test_cli_header_command() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("header")
        .arg(HS256_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"alg\": \"HS256\""))
        .stdout(predicate::str::contains("\"typ\": \"JWT\""));

    let mut cmd_compact = Command::cargo_bin("jwt-debugger").unwrap();
    cmd_compact
        .arg("header")
        .arg(HS256_TOKEN)
        .arg("--compact")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
        ));
}

#[test]
fn test_cli_payload_command() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("payload")
        .arg(HS256_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"John Doe\""))
        .stdout(predicate::str::contains("\"sub\": \"1234567890\""));

    let mut cmd_compact = Command::cargo_bin("jwt-debugger").unwrap();
    cmd_compact
        .arg("payload")
        .arg(HS256_TOKEN)
        .arg("--compact")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "{\"iat\":1516239022,\"name\":\"John Doe\",\"sub\":\"1234567890\"}",
        ));
}

#[test]
fn test_cli_signature_command_encodings() {
    // Base64URL
    let mut cmd_b64url = Command::cargo_bin("jwt-debugger").unwrap();
    cmd_b64url
        .arg("signature")
        .arg(HS256_TOKEN)
        .arg("--base64url")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ));

    // Hex
    let mut cmd_hex = Command::cargo_bin("jwt-debugger").unwrap();
    cmd_hex
        .arg("signature")
        .arg(HS256_TOKEN)
        .arg("--hex")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "49f94ac7044948c78a285d904f87f0a4c7897f7e8f3a4eb2255fda750b2cc397",
        ));

    // JSON
    let mut cmd_json = Command::cargo_bin("jwt-debugger").unwrap();
    let assert = cmd_json
        .arg("signature")
        .arg(HS256_TOKEN)
        .arg("--json")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["algorithm"], "HS256");
    assert_eq!(json["bytes"], 32);

    // Raw bytes
    let mut cmd_raw = Command::cargo_bin("jwt-debugger").unwrap();
    let assert_raw = cmd_raw
        .arg("signature")
        .arg(HS256_TOKEN)
        .arg("--raw")
        .assert()
        .success();
    assert_eq!(assert_raw.get_output().stdout.len(), 32);
}

#[test]
fn test_cli_claims_command() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("claims")
        .arg(HS256_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("Issued At (iat)"))
        .stdout(predicate::str::contains("Identity Claims"))
        .stdout(predicate::str::contains("Subject (sub):"))
        .stdout(predicate::str::contains("1234567890"));

    let mut cmd_json = Command::cargo_bin("jwt-debugger").unwrap();
    let assert = cmd_json
        .arg("claims")
        .arg(HS256_TOKEN)
        .arg("--json")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["standard_claims"]["sub"], "1234567890");
}
