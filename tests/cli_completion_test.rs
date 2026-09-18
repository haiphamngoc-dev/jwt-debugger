use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_completion_bash() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("completion")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::str::contains("_jwt__debugger"));
}

#[test]
fn test_cli_completion_zsh() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("completion")
        .arg("zsh")
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef jwt-debugger"));
}

#[test]
fn test_cli_completion_fish() {
    let mut cmd = Command::cargo_bin("jwt-debugger").unwrap();
    cmd.arg("completion")
        .arg("fish")
        .assert()
        .success()
        .stdout(predicate::str::contains("complete -c jwt-debugger"));
}
