use assert_cmd::Command;
use predicates::prelude::*;

mod common;
use common::{HS256_TOKEN, UNSECURED_TOKEN};

#[test]
fn test_cli_inspect_basic() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("inspect")
        .arg(HS256_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("Structure"))
        .stdout(predicate::str::contains("Header"))
        .stdout(predicate::str::contains("Claims"))
        .stdout(predicate::str::contains("Lifetime"))
        .stdout(predicate::str::contains("Signature"))
        .stdout(predicate::str::contains("Warnings"));
}

#[test]
fn test_cli_inspect_json_output() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    let assert = cmd
        .arg("inspect")
        .arg(HS256_TOKEN)
        .arg("--json")
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Valid JSON");

    assert_eq!(json["structure"]["segments"], 3);
    assert_eq!(json["header"]["alg"], "HS256");
    assert_eq!(json["payload"]["sub"], "1234567890");
    assert_eq!(json["signature"]["algorithm"], "HS256");
}

#[test]
fn test_cli_inspect_timezone_option() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("inspect")
        .arg(HS256_TOKEN)
        .arg("--timezone")
        .arg("UTC")
        .assert()
        .success()
        .stdout(predicate::str::contains("UTC"));

    let mut cmd_iana = Command::cargo_bin("jwt-debugger").unwrap();
    cmd_iana
        .arg("inspect")
        .arg(HS256_TOKEN)
        .arg("--timezone")
        .arg("Asia/Ho_Chi_Minh")
        .assert()
        .success();

    let mut cmd_bad_tz = Command::cargo_bin("jwt-debugger").unwrap();
    cmd_bad_tz
        .arg("inspect")
        .arg(HS256_TOKEN)
        .arg("--timezone")
        .arg("Invalid/Timezone_Name")
        .assert()
        .code(2) // EXIT_INVALID_USAGE
        .stderr(predicate::str::contains("Invalid timezone"));
}

#[test]
fn test_cli_inspect_security_warnings_alg_none() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("inspect")
        .arg(UNSECURED_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("UNSECURED_ALGORITHM"))
        .stdout(predicate::str::contains("MISSING_EXPIRATION"));
}

#[test]
fn test_cli_inspect_security_warnings_unusual_type_and_future_iat() {
    // Header: {"alg":"HS256","typ":"CUSTOM"}
    // Payload: {"sub":"123","iat":2500000000} (far future)
    let raw =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkNVU1RPTSJ9.eyJpYXQiOjI1MDAwMDAwMDAsInN1YiI6IjEyMyJ9.sig";
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("inspect")
        .arg(raw)
        .assert()
        .success()
        .stdout(predicate::str::contains("UNUSUAL_TYPE"))
        .stdout(predicate::str::contains("FUTURE_IAT"));
}
