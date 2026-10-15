use super::context;
use super::lifecycle::{self, LifecycleSummary};
use crate::bl::skills_config::SkillsConfig;
use anyhow::Result;
use blox::proto::SuspendWorkstationRequest;
use clap::{Arg, ArgMatches, Command};

pub(super) fn command() -> Command {
    Command::new("suspend").about("Request workstation suspension")
        .long_about("Request this transition for a workstation identified by canonical name or full ID. Reports the server response without waiting for the final state; inspect progress with `bl compute get <id>`. Use the full ID for an archived workstation.")
        .arg(Arg::new("workstation").value_name("WORKSTATION").required(true).value_parser(clap::builder::NonEmptyStringValueParser::new()))
}

pub(super) fn run(config: &SkillsConfig, args: &ArgMatches) -> Result<()> {
    let client = context::client(config, args, "suspend")?;
    let workstation = context::workstation(&client, args)?;
    let id = &workstation.workstation_id;
    let response = client
        .suspend_workstation(&SuspendWorkstationRequest {
            workstation_id: id.clone(),
        })
        .map_err(|error| lifecycle::map_error(error, "suspend", id))?;
    lifecycle::print_result(
        config,
        "suspend",
        id,
        LifecycleSummary {
            workstation_id: &response.workstation_id,
            status: Some(response.status),
            success: true,
            message: &response.message,
        },
        &response,
    )
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use serde_json::{json, Value};
    #[test]
    fn suspend_resolves_name_once_and_preserves_response() {
        let target = "9223372036854775806";
        let operation = "suspend";
        let reply = json!({"workstationId":target, "status":"WORKSTATION_STATUS_SUSPENDED", "message":"suspension initiated"});
        let auth = auth_service();
        let service = lifecycle_service(target, 200, reply.clone());
        let output = run_process(
            &auth,
            &service,
            &[
                "--json",
                "compute",
                operation,
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
        assert_eq!(output_json(&output), reply);
        assert_lifecycle_requests(auth, service, operation, target);
    }

    #[test]
    fn suspend_error_result_preserves_the_server_message() {
        let operation = "suspend";
        let response = json!({"workstationId":"target-id", "status":"WORKSTATION_STATUS_ERROR", "message":"snapshot failed"});
        let auth = auth_service();
        let service = lifecycle_service("target-id", 200, response.clone());
        let output = run_process(
            &auth,
            &service,
            &[
                "--json",
                "compute",
                operation,
                "123",
                "--base-url",
                "https://blox.test.blockstaging.build",
            ],
        );
        assert_eq!(output.status.code(), Some(1));
        let failure: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(failure["error"]["code"], "lifecycle_failed");
        assert!(failure["error"]["message"]
            .as_str()
            .unwrap()
            .contains(response["message"].as_str().unwrap()));
        assert_lifecycle_requests(auth, service, operation, "target-id");
    }

    #[test]
    fn suspend_unknown_acknowledgements_keep_the_target_and_never_retry() {
        let operation = "suspend";
        for (status, response) in [
            (
                503,
                json!({"code":"unavailable", "message":"lost acknowledgement"}),
            ),
            (200, json!("unexpected response")),
            (
                200,
                json!({"workstationId":"wrong-id", "message":"transition initiated"}),
            ),
            (200, json!({"message":"transition initiated"})),
        ] {
            let auth = auth_service();
            let service = lifecycle_service("known-id", status, response);
            let output = run_process(
                &auth,
                &service,
                &[
                    "--json",
                    "compute",
                    operation,
                    "123",
                    "--base-url",
                    "https://blox.test.blockstaging.build",
                ],
            );
            assert_eq!(output.status.code(), Some(5));
            let failure: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(failure["error"]["code"], "lifecycle_outcome_unknown");
            let message = failure["error"]["message"].as_str().unwrap();
            assert!(message.contains(operation));
            assert!(message.contains("bl compute get known-id"));
            assert!(message.contains("--base-url"));
            assert!(message.contains("before trying again"));
            assert_lifecycle_requests(auth, service, operation, "known-id");
        }
    }

    #[test]
    fn suspend_rejected_authentication_stops_before_workstation_resolution() {
        let operation = "suspend";
        let auth = MockService::start(401, json!({"error":"expired"}));
        let output = run_process(
            &auth,
            &auth,
            &[
                "--json",
                "compute",
                operation,
                "123",
                "--base-url",
                "https://blox.test.blockstaging.build",
            ],
        );
        assert_eq!(output.status.code(), Some(3));
        let failure: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(failure["error"]["code"], "auth_required");
        assert_eq!(auth.finish().0, "/api/goose/v1/auth/me");
    }

    #[test]
    fn suspend_definite_server_rejections_preserve_the_error_code() {
        let operation = "suspend";
        let auth = auth_service();
        let service = lifecycle_service(
            "known-id",
            400,
            json!({"code":"failed_precondition", "message":"transition is not allowed"}),
        );
        let output = run_process(
            &auth,
            &service,
            &[
                "--json",
                "compute",
                operation,
                "123",
                "--base-url",
                "https://blox.test.blockstaging.build",
            ],
        );
        assert_eq!(output.status.code(), Some(1));
        let failure: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(failure["error"]["code"], "failed_precondition");
        assert_lifecycle_requests(auth, service, operation, "known-id");
    }

    #[test]
    fn suspend_unexpected_status_does_not_claim_acceptance() {
        let operation = "suspend";
        for status in [0, 10] {
            let auth = auth_service();
            let service = lifecycle_service(
                "known-id",
                200,
                json!({"workstationId":"known-id", "status":status, "message":"inspect transition"}),
            );
            let output = run_process(
                &auth,
                &service,
                &[
                    "--json",
                    "compute",
                    operation,
                    "123",
                    "--base-url",
                    "https://blox.test.blockstaging.build",
                ],
            );
            assert_eq!(output.status.code(), Some(5));
            let failure: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(failure["error"]["code"], "lifecycle_outcome_unknown");
            assert!(failure["error"]["message"]
                .as_str()
                .unwrap()
                .contains("inspect transition"));
            assert_lifecycle_requests(auth, service, operation, "known-id");
        }
    }
}
