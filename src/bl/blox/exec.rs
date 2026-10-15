use super::context;
use super::context::map_error;
use crate::bl::display::terminal_safe_text;
use crate::bl::skills_api::SilentJsonExit;
use crate::bl::skills_api::{exit_codes, failure};
use crate::bl::skills_config::SkillsConfig;
use anyhow::{Context, Result};
use blox::proto::{ExecuteProcessRequest, StreamCommandOutputRequest};
use clap::{Arg, ArgMatches, Command};
use serde_json::Value;
use std::io::Write;

pub(super) fn command() -> Command {
    Command::new("exec")
                .about("Run a command on a workstation and follow its output")
                .long_about("Run a literal executable and arguments after --, stream stdout/stderr, and exit with the remote process status. Use explicit sh -c for shell expansion or pipelines. This is noninteractive: stdin and PTY are not supported. Interrupting or disconnecting may leave the command running. --json prints JSONL output events (protobuf bytes use base64), followed by an exit_code event.")
                .arg(Arg::new("workstation").value_name("WORKSTATION").required(true).value_parser(clap::builder::NonEmptyStringValueParser::new()))
                .arg(Arg::new("workdir").long("workdir").value_name("PATH").value_parser(clap::builder::NonEmptyStringValueParser::new()).help("Remote working directory (defaults to the workstation's configured directory)"))
                .arg(Arg::new("command").value_name("COMMAND").num_args(1..).last(true).required(true).help("Executable and arguments passed literally to the remote process"))
}

pub(super) fn run(config: &SkillsConfig, args: &ArgMatches) -> Result<()> {
    if args
        .get_many::<String>("command")
        .and_then(|mut command| command.next())
        .is_some_and(|command| command.is_empty())
    {
        return Err(failure(
            exit_codes::GENERAL,
            "invalid_command",
            "The remote executable must not be empty",
        ));
    }
    let client = context::client(config, args, "exec")?;
    let workstation = context::workstation(&client, args)?;
    let mut command = args
        .get_many::<String>("command")
        .context("expected command")?;
    let executable = command.next().context("expected executable")?.clone();
    let response = client
        .execute_process(&ExecuteProcessRequest {
            workstation_id: workstation.workstation_id.clone(),
            command: executable,
            args: command.cloned().collect(),
            working_dir: args
                .get_one::<String>("workdir")
                .cloned()
                .unwrap_or_default(),
            ..Default::default()
        })
        .map_err(|error| map_execute_start_error(error, &workstation.workstation_id))?;
    if response.command_id.is_empty() {
        return Err(execute_start_unknown(&workstation.workstation_id));
    }
    let command_id = response.command_id;
    config
        .style
        .verbose(&format!("Following Blox command {command_id}"));
    let mut exit_code = None;
    client
        .stream_command_output(
            &StreamCommandOutputRequest {
                workstation_id: workstation.workstation_id.clone(),
                command_id: command_id.clone(),
                follow: true,
                ..Default::default()
            },
            |output| {
                if config.json {
                    write_json_line(&serde_json::json!({
                        "workstation_id":workstation.workstation_id,
                        "command_id":command_id,
                        "output":output,
                    }))?;
                } else if !output.data.is_empty() {
                    match output.stream {
                        1 => {
                            let mut stdout = std::io::stdout().lock();
                            stdout.write_all(&output.data)?;
                            stdout.flush()?;
                        }
                        2 => {
                            let mut stderr = std::io::stderr().lock();
                            stderr.write_all(&output.data)?;
                            stderr.flush()?;
                        }
                        _ => anyhow::bail!("Blox returned output with an unsupported stream type"),
                    }
                }
                if let Some(code) = output.exit_code {
                    exit_code = Some(code);
                }
                Ok(())
            },
        )
        .map_err(|_| execute_follow_failed(&workstation.workstation_id, &command_id))?;
    let exit_code =
        exit_code.ok_or_else(|| execute_follow_failed(&workstation.workstation_id, &command_id))?;
    if config.json {
        write_json_line(
            &serde_json::json!({"workstation_id":workstation.workstation_id, "command_id":command_id, "exit_code":exit_code}),
        )?;
    }
    if exit_code != 0 {
        return Err(anyhow::Error::new(SilentJsonExit(exit_code)));
    }
    Ok(())
}

fn write_json_line(value: &Value) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, value).context("write Blox JSONL output")?;
    stdout
        .write_all(b"\n")
        .context("write Blox JSONL newline")?;
    stdout.flush().context("flush Blox JSONL output")
}

fn execute_start_unknown(workstation_id: &str) -> anyhow::Error {
    failure(exit_codes::NETWORK, "execute_outcome_unknown", format!("Blox execution result is unknown on workstation {}. Inspect its commands in Blox before running it again; the command may already be running. Preserve any --base-url override.", terminal_safe_text(workstation_id)))
}

fn map_execute_start_error(error: anyhow::Error, workstation_id: &str) -> anyhow::Error {
    if let Some(rpc) = error.downcast_ref::<blox::RpcError>() {
        if !matches!(
            rpc.code.as_str(),
            "unavailable" | "deadline_exceeded" | "unknown" | "internal" | "data_loss"
        ) {
            return map_error(error);
        }
    }
    execute_start_unknown(workstation_id)
}

fn execute_follow_failed(workstation_id: &str, command_id: &str) -> anyhow::Error {
    failure(exit_codes::NETWORK, "execute_output_incomplete", format!("Could not confirm the result of Blox command {} on workstation {}. The command may still be running; inspect it in Blox before running it again. Preserve any --base-url override.", terminal_safe_text(command_id), terminal_safe_text(workstation_id)))
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use serde_json::{json, Value};
    fn execute_service(outputs: Vec<Value>, terminal: Value) -> MockService {
        MockService::steps(vec![
            MockReply::Json(
                200,
                json!({"workstation":{"workstationId":"resolved-id", "name":"my-workstation"}}),
            ),
            MockReply::Json(200, json!({"commandId":"command-id"})),
            MockReply::Stream(outputs, terminal),
        ])
    }

    fn assert_execute_requests(auth: MockService, service: MockService) -> Vec<RecordedRequest> {
        let (path, _, _) = auth.finish();
        assert_eq!(path, "/api/goose/v1/auth/me");
        let requests = service.finish_all();
        for (_, headers, _) in &requests {
            assert_eq!(
                headers["authorization"],
                "BBIdentity blox-test-only.session"
            );
            assert!(!headers.contains_key("x-forwarded-identity-token"));
        }
        assert_eq!(requests.len(), 3);
        assert!(requests[0]
            .0
            .ends_with(".OrchestratorService/GetWorkstation"));
        assert!(requests[1]
            .0
            .ends_with(".OrchestratorService/ExecuteProcess"));
        assert!(requests[2]
            .0
            .ends_with(".OrchestratorService/StreamCommandOutput"));
        requests
    }
    #[test]
    fn execute_preserves_literal_arguments_and_raw_output_and_remote_exit_status() {
        let auth = auth_service();
        let service = execute_service(
            vec![
                json!({"stream":"STREAM_TYPE_STDOUT", "data":"SGVsbG8="}),
                json!({"stream":"STREAM_TYPE_STDERR", "data":"c3RkZXJy", "exitCode":7, "eof":true}),
            ],
            json!({}),
        );
        let output = run_process(
            &auth,
            &service,
            &[
                "compute",
                "exec",
                "my-workstation",
                "--workdir",
                "/work/my directory",
                "--base-url",
                "https://blox.test.blockstaging.build",
                "--",
                "printf",
                "a b",
                "$HOME; exit 1",
                "",
                "--help",
                "--json",
            ],
        );
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(process_stdout(&output), "Hello");
        assert_eq!(String::from_utf8_lossy(&output.stderr), "stderr");
        let requests = assert_execute_requests(auth, service);
        assert_eq!(requests[0].2, json!({"workstation":"my-workstation"}));
        assert_eq!(
            requests[1].2,
            json!({"workstationId":"resolved-id", "command":"printf", "args":["a b","$HOME; exit 1","","--help","--json"], "workingDir":"/work/my directory"})
        );
        assert_eq!(
            requests[2].2,
            json!({"workstationId":"resolved-id", "commandId":"command-id", "follow":true})
        );
    }

    #[test]
    fn execute_jsonl_events_end_with_remote_exit_without_an_extra_error() {
        let auth = auth_service();
        let service = execute_service(
            vec![
                json!({"stream":"STREAM_TYPE_STDOUT", "data":"SGVsbG8=", "resumeId":"1"}),
                json!({"exitCode":7, "eof":true}),
            ],
            json!({}),
        );
        let output = run_process(
            &auth,
            &service,
            &[
                "--json",
                "compute",
                "exec",
                "my-workstation",
                "--base-url",
                "https://blox.test.blockstaging.build",
                "--",
                "sh",
                "-c",
                "printf Hello; exit 7",
            ],
        );
        assert_eq!(output.status.code(), Some(7));
        assert!(output.stderr.is_empty());
        let events: Vec<Value> = process_stdout(&output)
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["output"]["data"], "SGVsbG8=");
        assert_eq!(events[0]["command_id"], "command-id");
        assert_eq!(
            events[2],
            json!({"command_id":"command-id", "workstation_id":"resolved-id", "exit_code":7})
        );
        assert_execute_requests(auth, service);
    }

    #[test]
    fn execute_silent_completion_requires_an_explicit_exit_code() {
        for remote_code in [0, 1] {
            let auth = auth_service();
            let service =
                execute_service(vec![json!({"exitCode":remote_code, "eof":true})], json!({}));
            let output = run_process(
                &auth,
                &service,
                &[
                    "compute",
                    "exec",
                    "my-workstation",
                    "--base-url",
                    "https://blox.test.blockstaging.build",
                    "--",
                    "true",
                ],
            );
            assert_eq!(output.status.code(), Some(remote_code));
            assert!(process_stdout(&output).is_empty());
            assert!(output.stderr.is_empty());
            assert_execute_requests(auth, service);
        }
    }

    #[test]
    fn execute_incomplete_or_failed_stream_never_claims_success() {
        for (outputs, terminal) in [
            (vec![json!({"eof":true})], json!({})),
            (
                vec![json!({"exitCode":0, "eof":true})],
                json!({"error":{"code":"unavailable", "message":"lost stream"}}),
            ),
        ] {
            let auth = auth_service();
            let service = execute_service(outputs, terminal);
            let output = run_process(
                &auth,
                &service,
                &[
                    "--json",
                    "compute",
                    "exec",
                    "my-workstation",
                    "--base-url",
                    "https://blox.test.blockstaging.build",
                    "--",
                    "true",
                ],
            );
            assert_eq!(output.status.code(), Some(5));
            let failure: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(failure["error"]["code"], "execute_output_incomplete");
            assert!(failure["error"]["message"]
                .as_str()
                .unwrap()
                .contains("command-id"));
            assert!(!process_stdout(&output).contains("exit_code"));
            assert_execute_requests(auth, service);
        }
    }

    #[test]
    fn execute_rejected_authentication_stops_before_any_workstation_request() {
        let auth = MockService::start(401, json!({"error":"expired"}));
        let output = run_process(
            &auth,
            &auth,
            &[
                "--json",
                "compute",
                "exec",
                "my-workstation",
                "--base-url",
                "https://blox.test.blockstaging.build",
                "--",
                "true",
            ],
        );
        assert_eq!(output.status.code(), Some(3));
        let failure: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(failure["error"]["code"], "auth_required");
        assert_eq!(auth.finish().0, "/api/goose/v1/auth/me");
    }

    #[test]
    fn ordinary_marketplace_json_errors_still_have_one_error_envelope() {
        let service = MockService::start(
            403,
            json!({"error":{"code":"forbidden", "message":"not permitted"}}),
        );
        let output = run_process(&service, &service, &["--json", "skills", "list"]);
        assert_eq!(output.status.code(), Some(4));
        let payload: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(payload["error"]["code"], "forbidden");
        assert_eq!(payload["error"]["exit_code"], 4);
        assert!(service.finish().0.contains("/v1/marketplace/skills"));
    }

    #[test]
    fn execute_start_rejection_or_unknown_result_does_not_retry() {
        for (status, reply, expected_code) in [
            (
                400,
                json!({"code":"failed_precondition", "message":"workstation is suspended"}),
                "failed_precondition",
            ),
            (
                503,
                json!({"code":"unavailable", "message":"lost acknowledgement"}),
                "execute_outcome_unknown",
            ),
            (200, json!({}), "execute_outcome_unknown"),
        ] {
            let auth = auth_service();
            let service = MockService::steps(vec![
                MockReply::Json(200, json!({"workstation":{"workstationId":"resolved-id"}})),
                MockReply::Json(status, reply),
            ]);
            let output = run_process(
                &auth,
                &service,
                &[
                    "--json",
                    "compute",
                    "exec",
                    "my-workstation",
                    "--base-url",
                    "https://blox.test.blockstaging.build",
                    "--",
                    "true",
                ],
            );
            assert!(!output.status.success());
            let failure: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(failure["error"]["code"], expected_code);
            assert_eq!(auth.finish().0, "/api/goose/v1/auth/me");
            let requests = service.finish_all();
            assert_eq!(requests.len(), 2);
            assert!(requests[1]
                .0
                .ends_with(".OrchestratorService/ExecuteProcess"));
        }
    }
}
