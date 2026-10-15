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
fn compute_help_is_available_without_authentication_or_network() {
    for operation in [
        None,
        Some("list"),
        Some("get"),
        Some("create"),
        Some("skus"),
        Some("exec"),
        Some("suspend"),
        Some("resume"),
        Some("delete"),
    ] {
        let mut canonical_help = None;
        for namespace in ["compute", "blox"] {
            let mut args = vec![namespace];
            args.extend(operation);
            args.push("--help");
            let (mut command, _home) = offline_command();
            let output = command.args(&args).output().expect("bl help");
            let (stdout, stderr) = text(&output);
            assert!(output.status.success(), "{stderr}");
            assert!(stdout.contains("Usage: bl compute"));
            assert!(!stdout.contains("--token"));
            assert!(!stdout.contains("StartWorkstation"));
            if let Some(expected) = &canonical_help {
                assert_eq!(&stdout, expected);
            } else {
                canonical_help = Some(stdout);
            }
        }
    }
}

#[test]
fn compute_is_registered_in_descriptions_and_shell_completions() {
    let (mut command, _home) = offline_command();
    let output = command.arg("--help").output().expect("bl help");
    assert!(output.status.success());
    let (stdout, _) = text(&output);
    assert!(stdout.contains("compute"));
    assert!(!stdout.contains("blox"));

    let (mut command, _home) = offline_command();
    let output = command
        .arg("--describe-commands")
        .output()
        .expect("describe bl");
    assert!(output.status.success());
    let description: Value = serde_json::from_slice(&output.stdout).expect("command description");
    assert!(!description["commands"]
        .as_array()
        .unwrap()
        .iter()
        .any(|command| command["name"] == "blox"));
    let compute = description["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|command| command["name"] == "compute")
        .expect("compute namespace");
    let mut names: Vec<_> = compute["commands"]
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

    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let (mut command, _home) = offline_command();
        let output = command
            .args(["completions", shell])
            .output()
            .expect("bl completions");
        assert!(output.status.success());
        let (stdout, _) = text(&output);
        assert!(stdout.contains("compute"), "{shell}");
        assert!(!stdout.contains("blox"), "{shell}");
    }
}

#[test]
fn invalid_compute_inputs_fail_before_session_loading() {
    for args in [
        vec!["compute", "list", "--limit=-1"],
        vec!["compute", "list", "--offset=-1"],
        vec!["compute", "get"],
        vec!["compute", "execute"],
        vec!["compute", "exec"],
        vec!["compute", "suspend"],
        vec!["compute", "resume"],
        vec!["compute", "delete"],
        vec!["compute", "exec", "my-workstation"],
        vec!["compute", "create", "--multiple", "0"],
        vec!["compute", "create", "--multiple=-1"],
        vec!["compute", "create", "--repo", "https://example.com/repo"],
        vec!["compute", "create", "--cpu", "2"],
        vec!["compute", "create", "--memory", "4"],
        vec!["compute", "create", "--provider", "kube"],
        vec!["compute", "create", "--architecture", "amd64"],
        vec![
            "compute",
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
            vec!["--json", "compute", "exec", "ws", "--", ""],
            "invalid_command",
        ),
        (
            vec!["--json", "compute", "list", "--limit", "0", "--offset", "1"],
            "invalid_pagination",
        ),
        (
            vec![
                "--json",
                "compute",
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
