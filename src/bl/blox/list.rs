use super::context;
use super::context::map_error;
use super::output::status_text;
use crate::bl::display::{print_json, terminal_safe_text};
use crate::bl::skills_api::{exit_codes, failure};
use crate::bl::skills_config::SkillsConfig;
use anyhow::{Context, Result};
use blox::proto::ListWorkstationsRequest;
use clap::ArgAction;
use clap::{Arg, ArgMatches, Command};
pub(super) fn command() -> Command {
    Command::new("list")
        .about("List your workstations")
        .arg(
            Arg::new("include-deleted")
                .long("include-deleted")
                .action(ArgAction::SetTrue)
                .help("Include archived workstations"),
        )
        .arg(
            Arg::new("limit")
                .long("limit")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(i32).range(0..))
                .default_value("100")
                .help("Maximum results (0 means all)"),
        )
        .arg(
            Arg::new("offset")
                .long("offset")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(i32).range(0..))
                .default_value("0")
                .help("Number of results to skip"),
        )
}

pub(super) fn run(config: &SkillsConfig, args: &ArgMatches) -> Result<()> {
    if args.get_one::<i32>("limit") == Some(&0)
        && args
            .get_one::<i32>("offset")
            .is_some_and(|offset| *offset > 0)
    {
        return Err(failure(
            exit_codes::GENERAL,
            "invalid_pagination",
            "--offset requires a nonzero --limit",
        ));
    }
    let client = context::client(config, args, "list")?;
    let response = client
        .list_workstations(&ListWorkstationsRequest {
            include_deleted: Some(args.get_flag("include-deleted")),
            page_limit: *args
                .get_one::<i32>("limit")
                .context("expected result limit")?,
            page_offset: *args
                .get_one::<i32>("offset")
                .context("expected result offset")?,
            skip_access_details: true,
        })
        .map_err(map_error)?;
    if config.json {
        print_json(&response)
    } else {
        if response.workstations.is_empty() {
            println!("No workstations found.");
        } else {
            println!("ID\tNAME\tSTATUS\tPROVIDER");
            for workstation in &response.workstations {
                println!(
                    "{}\t{}\t{}\t{}",
                    terminal_safe_text(&workstation.workstation_id),
                    terminal_safe_text(&workstation.name),
                    status_text(workstation.status),
                    terminal_safe_text(&workstation.provider)
                );
            }
            println!(
                "{} of {} workstations",
                response.workstations.len(),
                response.total_count
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use serde_json::{json, Value};

    #[test]
    fn list_uses_shared_session_and_preserves_protobuf_json() {
        for namespace in ["compute", "blox"] {
            let auth = auth_service();
            let service = MockService::start(
                200,
                json!({"workstations":[{"workstationId":"9223372036854775806", "name":"project", "status":999}], "totalCount":"9007199254740993", "recentlyDeletedCount":"7"}),
            );
            let output = run_process(
                &auth,
                &service,
                &[
                    namespace,
                    "--base-url",
                    "https://blox.public.builderlab.xyz",
                    "list",
                    "--include-deleted",
                    "--limit",
                    "2",
                    "--offset",
                    "3",
                    "--json",
                ],
            );
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("9007199254740993"));
            assert!(stdout.contains("9223372036854775806"));
            assert!(!stdout.contains("999")); // Forward enum variants become unspecified.

            let (path, body) = assert_shared_auth(auth, service);
            assert!(
                path.ends_with("/OrchestratorService/ListWorkstations")
                    || path.ends_with(".OrchestratorService/ListWorkstations")
            );
            assert_eq!(
                body,
                json!({"includeDeleted":true, "pageLimit":2, "pageOffset":3, "skipAccessDetails":true})
            );
        }
    }

    #[test]
    fn rejected_shared_session_stops_before_blox_request() {
        let auth = MockService::start(401, json!({"error":"expired"}));
        let output = run_process(
            &auth,
            &auth,
            &[
                "compute",
                "list",
                "--base-url",
                "https://blox.test.blockstaging.build",
                "--json",
            ],
        );
        assert_eq!(output.status.code(), Some(3));
        let payload: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(payload["error"]["code"], "auth_required");
        assert!(payload["error"]["message"]
            .as_str()
            .unwrap()
            .contains("bl auth login"));
        let (path, _, _) = auth.finish();
        assert_eq!(path, "/api/goose/v1/auth/me");
    }
}
