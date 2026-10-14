//! Offline checks of the compiled Blox command surface.
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

fn offline_command() -> (Command, TempDir) {
    let home = tempfile::tempdir().expect("temporary bl home");
    let mut command = Command::new(env!("CARGO_BIN_EXE_bl"));
    command
        .env_clear()
        .env("BL_HOME", home.path())
        .env("HOME", home.path())
        .env("BL_AUTH_STORAGE", "file")
        .env("BL_AUTH_STORAGE_FILE", home.path().join("session.json"))
        .env("KGOOSE_BASE_URL", "https://app.builderlab.xyz");
    (command, home)
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8(output.stdout.clone()).expect("stdout UTF-8"),
        String::from_utf8(output.stderr.clone()).expect("stderr UTF-8"),
    )
}

#[test]
fn blox_help_is_available_without_authentication_or_network() {
    for args in [
        vec!["blox", "--help"],
        vec!["blox", "list", "--help"],
        vec!["blox", "get", "--help"],
        vec!["blox", "create", "--help"],
        vec!["blox", "skus", "--help"],
        vec!["blox", "exec", "--help"],
        vec!["blox", "suspend", "--help"],
        vec!["blox", "resume", "--help"],
        vec!["blox", "delete", "--help"],
    ] {
        let (mut command, _home) = offline_command();
        let output = command.args(&args).output().expect("bl help");
        let (stdout, stderr) = text(&output);
        assert!(output.status.success(), "{stderr}");
        assert!(stdout.contains("Usage: bl blox"));
        assert!(!stdout.contains("--token"));
        assert!(!stdout.contains("StartWorkstation"));
    }
}

#[test]
fn blox_is_registered_in_descriptions_and_shell_completions() {
    let (mut command, _home) = offline_command();
    let output = command
        .arg("--describe-commands")
        .output()
        .expect("describe bl");
    assert!(output.status.success());
    let description: Value = serde_json::from_slice(&output.stdout).expect("command description");
    let blox = description["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|command| command["name"] == "blox")
        .expect("blox namespace");
    let mut names: Vec<_> = blox["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|command| command["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["create", "delete", "exec", "get", "list", "resume", "skus", "suspend"]
    );

    let (mut command, _home) = offline_command();
    let output = command
        .args(["completions", "bash"])
        .output()
        .expect("bl completions");
    assert!(output.status.success());
    assert!(text(&output).0.contains("blox"));
}

#[test]
fn invalid_blox_inputs_fail_before_session_loading() {
    for args in [
        vec!["blox", "list", "--limit=-1"],
        vec!["blox", "list", "--offset=-1"],
        vec!["blox", "get"],
        vec!["blox", "execute"],
        vec!["blox", "exec"],
        vec!["blox", "suspend"],
        vec!["blox", "resume"],
        vec!["blox", "delete"],
        vec!["blox", "exec", "my-workstation"],
        vec!["blox", "create", "--multiple", "0"],
        vec!["blox", "create", "--multiple=-1"],
        vec!["blox", "create", "--repo", "https://example.com/repo"],
        vec!["blox", "create", "--cpu", "2"],
        vec!["blox", "create", "--memory", "4"],
        vec!["blox", "create", "--provider", "kube"],
        vec!["blox", "create", "--architecture", "amd64"],
        vec![
            "blox",
            "create",
            "my-workstation",
            "https://example.com/repo",
        ],
    ] {
        let (mut command, _home) = offline_command();
        let output = command.args(&args).output().expect("invalid bl input");
        let (_, stderr) = text(&output);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(!stderr.contains("auth login"));
    }

    for (args, expected_code) in [
        (
            vec!["--json", "blox", "exec", "ws", "--", ""],
            "invalid_command",
        ),
        (
            vec!["--json", "blox", "list", "--limit", "0", "--offset", "1"],
            "invalid_pagination",
        ),
        (
            vec![
                "--json",
                "blox",
                "list",
                "--base-url",
                "https://unapproved.example",
            ],
            "invalid_endpoint",
        ),
    ] {
        let (mut command, _home) = offline_command();
        let output = command.args(&args).output().expect("early validation");
        let (_, stderr) = text(&output);
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        let error: Value = serde_json::from_str(&stderr).expect("JSON failure");
        assert_eq!(error["error"]["code"], expected_code);
        assert!(!stderr.contains("auth login"));
    }
}
