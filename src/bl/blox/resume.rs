use super::context;
use super::lifecycle::{self, LifecycleSummary};
use crate::bl::skills_config::SkillsConfig;
use anyhow::Result;
use blox::proto::ResumeWorkstationRequest;
use clap::{Arg, ArgMatches, Command};

pub(super) fn command() -> Command {
    Command::new("resume").about("Request workstation resumption")
        .long_about("Request this transition for a workstation identified by canonical name or full ID. Reports the server response without waiting for the final state; inspect progress with `bl blox get <id>`. Use the full ID for an archived workstation.")
        .arg(Arg::new("workstation").value_name("WORKSTATION").required(true).value_parser(clap::builder::NonEmptyStringValueParser::new()))
}

pub(super) fn run(config: &SkillsConfig, args: &ArgMatches) -> Result<()> {
    let client = context::client(config, args, "resume")?;
    let workstation = context::workstation(&client, args)?;
    let id = &workstation.workstation_id;
    let response = client
        .resume_workstation(&ResumeWorkstationRequest {
            workstation_id: id.clone(),
        })
        .map_err(|error| lifecycle::map_error(error, "resume", id))?;
    lifecycle::print_result(
        config,
        "resume",
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
    fn resume_resolves_name_once_and_preserves_response() {
        let target = "9223372036854775806";
        let operation = "resume";
        let reply = json!({"workstationId":target, "status":"WORKSTATION_STATUS_QUEUED", "message":"resume queued"});
        let auth = auth_service();
        let service = lifecycle_service(target, 200, reply.clone());
        let output = run_process(
            &auth,
            &service,
            &[
                "--json",
                "blox",
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
    fn resume_degraded_result_preserves_the_server_message() {
        let operation = "resume";
        let response = json!({"workstationId":"target-id", "status":"WORKSTATION_STATUS_DEGRADED", "message":"bootstrap failed"});
        let auth = auth_service();
        let service = lifecycle_service("target-id", 200, response.clone());
        let output = run_process(
            &auth,
            &service,
            &[
                "--json",
                "blox",
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
    fn resume_unknown_acknowledgements_keep_the_target_and_never_retry() {
        let operation = "resume";
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
                    "blox",
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
            assert!(message.contains("bl blox get known-id"));
            assert!(message.contains("--base-url"));
            assert!(message.contains("before trying again"));
            assert_lifecycle_requests(auth, service, operation, "known-id");
        }
    }

    #[test]
    fn resume_rejected_authentication_stops_before_workstation_resolution() {
        let operation = "resume";
        let auth = MockService::start(401, json!({"error":"expired"}));
        let output = run_process(
            &auth,
            &auth,
            &[
                "--json",
                "blox",
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
    fn resume_definite_server_rejections_preserve_the_error_code() {
        let operation = "resume";
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
                "blox",
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
    fn resume_unexpected_status_does_not_claim_acceptance() {
        let operation = "resume";
        for status in [999, 7] {
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
                    "blox",
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

    #[test]
    fn resume_accepts_initial_states_and_full_archived_ids_without_claiming_readiness() {
        for status in [
            "WORKSTATION_STATUS_QUEUED",
            "WORKSTATION_STATUS_CREATING",
            "WORKSTATION_STATUS_STARTING",
            "WORKSTATION_STATUS_RUNNING",
        ] {
            let auth = auth_service();
            let service = lifecycle_service(
                "archived-id",
                200,
                json!({"workstationId":"archived-id", "status":status, "message":"resume requested"}),
            );
            let output = run_process(
                &auth,
                &service,
                &[
                    "blox",
                    "resume",
                    "archived-id",
                    "--base-url",
                    "https://blox.test.blockstaging.build",
                ],
            );
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = process_stdout(&output);
            assert!(stdout.contains("Request accepted: resume"));
            assert!(stdout.contains("Server status:"));
            assert!(stdout.contains("bl blox get archived-id"));
            assert!(!stdout.contains("ready"));
            assert_lifecycle_requests(auth, service, "resume", "archived-id");
        }
    }
}
