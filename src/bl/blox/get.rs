use super::context;
use super::context::map_error;
use super::output::status_text;
use crate::bl::display::{print_json, terminal_safe_text};
use crate::bl::skills_api::{exit_codes, failure};
use crate::bl::skills_config::SkillsConfig;
use anyhow::{Context, Result};
use blox::proto::WorkstationSummary;
use clap::{Arg, ArgMatches, Command};
pub(super) fn command() -> Command {
    Command::new("get")
        .about("Get a workstation by canonical name or full ID")
        .arg(
            Arg::new("workstation")
                .value_name("WORKSTATION")
                .required(true)
                .value_parser(clap::builder::NonEmptyStringValueParser::new()),
        )
}

pub(super) fn run(config: &SkillsConfig, args: &ArgMatches) -> Result<()> {
    let client = context::client(config, args, "get")?;
    let identifier = args
        .get_one::<String>("workstation")
        .context("expected workstation name or ID")?;
    let response = client.get_workstation(identifier).map_err(map_error)?;
    let workstation = response.workstation.as_ref().ok_or_else(|| {
        failure(
            exit_codes::GENERAL,
            "invalid_response",
            "Blox returned no workstation",
        )
    })?;
    if config.json {
        print_json(&response)
    } else {
        print_workstation(workstation);
        Ok(())
    }
}

fn print_workstation(workstation: &WorkstationSummary) {
    for (label, value) in [
        ("ID", workstation.workstation_id.as_str()),
        ("Name", workstation.name.as_str()),
        ("Provider", workstation.provider.as_str()),
        ("Created", workstation.created_at.as_str()),
        ("Last used", workstation.last_used_at.as_str()),
        ("Message", workstation.message.as_str()),
    ] {
        println!("{label}: {}", terminal_safe_text(value));
    }
    println!("Status: {}", status_text(workstation.status));
    if let Some(label) = &workstation.display_name {
        println!("Display name: {}", terminal_safe_text(label));
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use serde_json::{json, Value};

    #[test]
    fn get_forwards_the_selector_unchanged() {
        let auth = auth_service();
        let service = MockService::start(
            200,
            json!({"workstation":{"workstationId":"123", "name":"123", "status":"WORKSTATION_STATUS_SUSPENDING"}}),
        );
        let output = run_process(
            &auth,
            &service,
            &[
                "compute",
                "get",
                "123",
                "--base-url",
                "https://blox.test.blockstaging.build",
            ],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("Status: suspending"));
        let (_, body) = assert_shared_auth(auth, service);
        assert_eq!(body, json!({"workstation":"123"}));
    }

    #[test]
    fn errors_use_shared_json_format_and_redact_the_session() {
        let auth = auth_service();
        let service = MockService::start(
            403,
            json!({"code":"permission_denied", "message":"denied blox-test-only.session"}),
        );
        let output = run_process(
            &auth,
            &service,
            &[
                "compute",
                "get",
                "project",
                "--base-url",
                "https://blox.test.blockstaging.build",
                "--json",
            ],
        );
        assert_eq!(output.status.code(), Some(4));
        let stderr = String::from_utf8_lossy(&output.stderr);
        let payload: Value = serde_json::from_str(stderr.trim()).unwrap();
        assert_eq!(payload["error"]["code"], "permission_denied");
        assert_eq!(payload["error"]["exit_code"], 4);
        assert!(!stderr.contains("blox-test-only.session"));
        assert_shared_auth(auth, service);
    }

    #[test]
    fn missing_workstation_is_an_error() {
        let auth = auth_service();
        let service = MockService::start(200, json!({}));
        let output = run_process(
            &auth,
            &service,
            &[
                "compute",
                "get",
                "project",
                "--base-url",
                "https://blox.test.blockstaging.build",
                "--json",
            ],
        );
        assert_eq!(output.status.code(), Some(1));
        let payload: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(payload["error"]["code"], "invalid_response");
        assert_shared_auth(auth, service);
    }
}
