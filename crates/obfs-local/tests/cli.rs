// SPDX-License-Identifier: GPL-3.0-or-later

use std::process::Command;

#[test]
fn help_and_invalid_arguments_exit_without_starting_proxy() {
    let executable = env!("CARGO_BIN_EXE_obfs-local");
    let output = Command::new(executable).arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for option in [
        "-s",
        "-p",
        "-l",
        "-t",
        "-c",
        "-b",
        "-i",
        "-a",
        "-f",
        "-n",
        "--obfs",
        "--obfs-host",
        "--obfs-uri",
        "--http-method",
        "--fast-open",
        "--mptcp",
    ] {
        assert!(help.contains(option), "missing option {option}");
    }
    let output = Command::new(executable).arg("--invalid-option").output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn malformed_sip003_environment_reports_error_without_crashing() {
    let output = Command::new(env!("CARGO_BIN_EXE_obfs-local"))
        .env("SS_REMOTE_HOST", "127.0.0.1")
        .env("SS_REMOTE_PORT", "invalid")
        .env("SS_LOCAL_HOST", "127.0.0.1")
        .env("SS_LOCAL_PORT", "12345")
        .env("SS_PLUGIN_OPTIONS", "obfs=http")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8(output.stderr).unwrap().contains("server_port"));
}
