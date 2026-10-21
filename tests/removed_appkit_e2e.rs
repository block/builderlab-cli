//! Removed local extensions must not appear or execute through either binary.
#![cfg(unix)]

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};

use common::{output_text, write_fake_executable, MockServer};

fn tools_command(server: &MockServer, builderlab: bool, temp: &Path) -> Command {
    let mut command = if builderlab {
        server.bl_tools_command()
    } else {
        server.command()
    };
    command
        .env("BL_AUTH_STORAGE", "file")
        .env("BL_AUTH_STORAGE_FILE", temp.join("auth.json"));
    command
}

#[test]
fn removed_appkit_is_absent_from_help_and_discovery_even_if_advertised_remotely() {
    let temp = tempfile::tempdir().expect("create temp directory");
    let catalog = temp.path().join("extensions.yaml");
    fs::write(
        &catalog,
        "- name: appkit\n  about: Must not appear\n- name: utils\n  about: Utility helpers\n",
    )
    .expect("write static catalog");

    for builderlab in [false, true] {
        for arg in ["--help", "--describe-commands"] {
            let responses = if builderlab {
                vec![common::MockResponse::json(json!({"extensions": [
                    {"name": "appkit", "description": "Must not appear"},
                    {"name": "utils", "description": "Utility helpers"}
                ]}))]
            } else {
                vec![]
            };
            let server = MockServer::start(responses);
            let output = tools_command(&server, builderlab, temp.path())
                .env("KGOOSE_EXTENSIONS_CATALOG", &catalog)
                .arg(arg)
                .output()
                .expect("discover tools");
            let requests = server.finish();
            let (stdout, stderr) = output_text(&output);

            assert!(output.status.success(), "{builderlab} {arg}: {stderr}");
            assert!(!stdout.contains("appkit"), "{stdout}");
            assert!(!stdout.contains("Cloudflare"), "{stdout}");
            if arg == "--describe-commands" {
                let description: Value = serde_json::from_str(&stdout).expect("parse discovery");
                assert_eq!(description["commands"][0]["name"], "utils");
                assert_eq!(description["commands"].as_array().unwrap().len(), 1);
            } else {
                assert!(stdout.contains("utils"), "{stdout}");
            }
            assert_eq!(requests.len(), usize::from(builderlab));
        }
    }

    let output = common::bl_command()
        .args(["apps", "--help"])
        .output()
        .expect("inspect Apps Platform help");
    let (stdout, stderr) = output_text(&output);
    assert!(output.status.success(), "{stderr}");
    assert!(stdout.contains("Apps Platform"));
    assert!(!stdout.contains("appkit"), "{stdout}");
    assert!(!stdout.contains("Cloudflare"), "{stdout}");
}

#[test]
fn removed_appkit_rejects_execution_and_targeted_metadata_without_local_or_remote_fallback() {
    let temp = tempfile::tempdir().expect("create temp directory");
    let marker = temp.path().join("executed");
    let args: &[&[&str]] = &[
        &["appkit"],
        &["appkit", "--help"],
        &["appkit", "deploy"],
        &["appkit", "deploy", "--timeout", "invalid", "--summary"],
        &["--", "appkit", "deploy"],
        &["--playpen", "appkit", "appkit", "deploy"],
        &["--playpen=appkit", "appkit", "deploy"],
        &["--timeout", "3", "appkit", "deploy"],
        &["--describe-commands", "appkit"],
        &["appkit", "--describe-commands"],
        &["appkit", "deploy", "--describe-commands"],
        &["--summary", "appkit"],
        &["appkit", "--summary"],
        &["--describe-commands", "--", "appkit"],
        &["--summary", "--", "appkit"],
    ];

    for appkit_on_path in [false, true] {
        let fake_bin = temp
            .path()
            .join(if appkit_on_path { "both" } else { "uvx-only" });
        fs::create_dir(&fake_bin).expect("create fake PATH");
        let script = "#!/bin/sh\nprintf invoked > \"$APPKIT_TEST_MARKER\"\nexit 71\n";
        write_fake_executable(&fake_bin, "uvx", script);
        if appkit_on_path {
            write_fake_executable(&fake_bin, "appkit", script);
        }

        for builderlab in [false, true] {
            for args in args {
                let server = MockServer::start(vec![]);
                let output = tools_command(&server, builderlab, temp.path())
                    .env("PATH", &fake_bin)
                    .env("APPKIT_TEST_MARKER", &marker)
                    .args(*args)
                    .output()
                    .expect("run removed App Kit command");
                let requests = server.finish();
                let (stdout, stderr) = output_text(&output);

                assert!(!output.status.success(), "{builderlab} {args:?}: {stdout}");
                assert!(!stderr.is_empty(), "{builderlab} {args:?}: {stderr}");
                if !args.contains(&"invalid") {
                    assert!(stderr.contains("unknown extension `appkit`"), "{stderr}");
                }
                assert!(stdout.is_empty(), "{stdout}");
                assert!(!marker.exists(), "local executable ran for {args:?}");
                assert!(
                    requests.is_empty(),
                    "remote fallback for {args:?}: {requests:?}"
                );
            }
        }
    }
}
