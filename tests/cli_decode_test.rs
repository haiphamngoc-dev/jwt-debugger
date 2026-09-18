use assert_cmd::Command;
use predicates::prelude::*;

mod common;
use common::{HS256_TOKEN, create_temp_file};

#[test]
fn test_cli_decode_positional_arg() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("decode")
        .arg(HS256_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("Header"))
        .stdout(predicate::str::contains("Payload"))
        .stdout(predicate::str::contains("Signature"))
        .stdout(predicate::str::contains("\"alg\": \"HS256\""))
        .stdout(predicate::str::contains("\"sub\": \"1234567890\""));
}

#[test]
fn test_cli_decode_flag_token() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("decode")
        .arg("--token")
        .arg(HS256_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"alg\": \"HS256\""));
}

#[test]
fn test_cli_decode_token_file() {
    let temp_file = create_temp_file(HS256_TOKEN);
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("decode")
        .arg("--token-file")
        .arg(temp_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("\"alg\": \"HS256\""));
}

#[test]
fn test_cli_decode_stdin_pipe() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("decode")
        .write_stdin(HS256_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"alg\": \"HS256\""));
}

#[test]
fn test_cli_decode_json_output() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    let assert = cmd
        .arg("decode")
        .arg(HS256_TOKEN)
        .arg("--json")
        .assert()
        .success();

    let output_str = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json_val: serde_json::Value =
        serde_json::from_str(&output_str).expect("Valid JSON expected");
    assert_eq!(json_val["header"]["alg"], "HS256");
    assert_eq!(json_val["payload"]["sub"], "1234567890");
    assert_eq!(json_val["signature"]["algorithm"], "HS256");
    assert_eq!(json_val["metadata"]["segments"], 3);
}

#[test]
fn test_cli_decode_compact_output() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("decode")
        .arg(HS256_TOKEN)
        .arg("--compact")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
        ))
        .stdout(predicate::str::contains(
            "{\"iat\":1516239022,\"name\":\"John Doe\",\"sub\":\"1234567890\"}",
        ));
}

#[test]
fn test_cli_decode_quiet_flag() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("decode")
        .arg(HS256_TOKEN)
        .arg("--quiet")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_cli_decode_malformed_token_exit_code() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    // Only 2 segments
    cmd.arg("decode")
        .arg("invalid.jwt")
        .assert()
        .code(3) // EXIT_MALFORMED_JWT
        .stderr(predicate::str::contains("Error parsing JWT"));
}

#[test]
fn test_cli_decode_conflicting_inputs() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("decode")
        .arg(HS256_TOKEN)
        .arg("--token")
        .arg(HS256_TOKEN)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Conflicting token input options"));
}
