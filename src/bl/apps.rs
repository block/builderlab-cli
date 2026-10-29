//! External BuilderLab Apps Platform control-plane commands.
//!
//! This module serves the BuilderLab Apps Platform in `bb-block` and the
//! multi-tenant `bb-public` environment.
//!
//! The CLI sends its stored bbidentity session only to the allowlisted Compose
//! control-plane origins. Public ingress authorizes that session through kgoose
//! `ext_authz` and removes it before forwarding the request internally. Compose
//! never receives the session credential.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use builderlab_auth::auth_login::{
    auth_url, build_auth_http_client, playpen_baggage, AuthMeResponse, CLI_USER_AGENT,
};
use builderlab_auth::auth_storage::StoredSessionCredential;
use builderlab_auth::SESSION_CREDENTIAL_HEADER;
use clap::{Arg, ArgGroup, ArgMatches, Command};
use reqwest::blocking::{multipart, Client, Request, RequestBuilder, Response};
use reqwest::header::{HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{json, Map, Value};

use super::auth_login::verify_stored_session;
use super::auth_storage::{default_session_storage, session_storage_key_from_config};
use super::display::{print_json, terminal_safe_text, Style};
use super::runner;
#[cfg(test)]
use super::skills_api::failure_info;
use super::skills_api::{exit_codes, failure, failure_trace_id, with_failure_trace_id, CliFailure};
use super::skills_config::{kgoose_service_url, SkillsConfig};

const APPS_BASE_URL_ENV_VAR: &str = "BL_APPS_CONTROL_PLANE_URL";
const APPS_CLIENT_VERSION_ENV_VAR: &str = "BL_APPS_CLIENT_VERSION";
// Apps compatibility evolves independently of the standalone CLI release
// numbering. Keep the beta package version in --version and User-Agent.
const APPS_PROTOCOL_VERSION: &str = "0.2.0";
#[cfg(test)]
const APPS_E2E_CONTROL_PLANE_URL_ENV_VAR: &str = "BL_APPS_E2E_CONTROL_PLANE_URL";
#[cfg(test)]
const APPS_E2E_AUTH_URL_ENV_VAR: &str = "BL_APPS_E2E_AUTH_URL";
#[cfg(test)]
const APPS_E2E_CREDENTIAL_ENV_VAR: &str = "BL_APPS_E2E_CREDENTIAL";
const APPS_CONTRACT_PATH: &str = "/v1/agent/contract";
const APPS_PLAN_PATH: &str = "/v1/agent/apps/plan";
const MAX_DEBUG_TAIL_LINES: u16 = 1000;
const HOTPOD_AGENT_CLIENT_VERSION_HEADER: &str = "X-Hotpod-Agent-Client-Version";
const HOTPOD_TRACE_ID_HEADER: &str = "X-Hotpod-Trace-Id";
// Compose may synchronously wait up to two minutes for an initialize or
// deploy rollout. Leave enough headroom for the response to traverse ingress.
const CONTROL_PLANE_REQUEST_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const CONTROL_PLANE_RESPONSE_MAX_BYTES: usize = 2 * 1024 * 1024;
const TRUSTED_CONTROL_PLANE_HOSTS: &[&str] = &[
    "compose-ctrl.test.blockstaging.build",
    "compose-ctrl.block.builderlabstaging.xyz",
    "compose-ctrl.block.builderlab.xyz",
    "compose-ctrl.apps.builderlab.xyz",
    "compose-ctrl.apps.builderlabstaging.xyz",
    "compose-ctrl.public.builderlab.xyz",
    "compose-ctrl.public.builderlabstaging.xyz",
    "compose-ctrl.builderlab.xyz",
    "compose-ctrl.builderlabstaging.xyz",
];

pub fn command() -> Command {
    let about = "Manage apps through the BuilderLab Apps Platform. `bl apps get` shows who can open an app and links to Share & manage. `bl apps visibility` switches an app between your workspace and only you, and `bl apps community` shares it with a Buzz community.";
    Command::new("apps")
        .about("Manage apps through Apps Platform")
        .long_about(about)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .disable_help_subcommand(true)
        .subcommand(control_plane_args(
            Command::new("contract")
                .about(
                    "Read the control-plane contract, runtime metadata, and supported operations",
                ),
        ))
        .subcommand(control_plane_args(
            Command::new("list")
                .about("List apps the current caller can manage")
                .long_about(
                    "List Apps Platform apps the current caller owns or is approved to publish. \
                     Deleted apps remain hidden unless explicitly included. Use --scope owned \
                     for owner quota metadata when accounting is available. The list count is \
                     visible apps, not quota usage. Accounting-only limits are informational; \
                     enforcement is controlled by the server. An unavailable tier does not \
                     prevent listing or inspecting existing apps.",
                )
                .arg(
                    Arg::new("scope")
                        .long("scope")
                        .value_name("SCOPE")
                        .value_parser(["manageable", "owned", "publisher"])
                        .help("Filter by relationship to the app (control-plane default: manageable)"),
                )
                .arg(
                    Arg::new("include-deleted")
                        .long("include-deleted")
                        .action(clap::ArgAction::SetTrue)
                        .help("Include logically deleted apps"),
                ),
        ))
        .subcommand(control_plane_args(app_get_command("get")))
        .subcommand(control_plane_args(
            Command::new("versions")
                .about("List active and rollback-candidate versions for an app")
                .arg(
                    Arg::new("app-id")
                        .value_name("APP_ID")
                        .required(true)
                        .help("App identifier returned by `bl apps list` or `bl apps create`"),
                )
                .arg(
                    Arg::new("environment")
                        .long("environment")
                        .value_name("ENVIRONMENT")
                        .help("Optional Compose environment override"),
                ),
        ))
        .subcommand(control_plane_args(
            Command::new("create")
                .about("Plan and reserve an app")
                .long_about(
                    "Plan an app identity through Apps Platform, reserve that exact ID, then \
                     initialize it only when the returned plan marks initialization as required \
                     or recommended. Supply a descriptive DNS-safe app ID or a human-readable \
                     name from which the control plane can derive one. If creation is interrupted \
                     after reservation, repeat the same command to reconcile the caller-owned \
                     idle reservation and continue initialization. For owner_site_limit_reached, \
                     inspect `bl apps list --scope owned` on the same control plane. Existing \
                     apps remain manageable above the limit. Retry creation explicitly only \
                     after a fresh server response confirms capacity; do not retry automatically \
                     during owner reconciliation or a tier outage.",
                )
                .group(
                    ArgGroup::new("app-identity")
                        .args(["app-id", "name"])
                        .multiple(true)
                        .required(true),
                )
                .arg(
                    Arg::new("app-id")
                        .long("app-id")
                        .value_name("APP_ID")
                        .value_parser(clap::builder::NonEmptyStringValueParser::new())
                        .help("Descriptive DNS-safe app identifier to reserve exactly"),
                )
                .arg(
                    Arg::new("name")
                        .long("name")
                        .value_name("NAME")
                        .value_parser(clap::builder::NonEmptyStringValueParser::new())
                        .help("Human-readable app name"),
                )
                .arg(
                    Arg::new("environment")
                        .long("environment")
                        .value_name("ENVIRONMENT")
                        .help("Compose environment to plan and initialize"),
                )
                .arg(
                    Arg::new("runtime-profile")
                        .long("runtime-profile")
                        .value_name("PROFILE")
                        .help("Artifact runtime profile advertised by the control-plane contract"),
                )
                .arg(
                    Arg::new("persistence")
                        .long("persistence")
                        .value_name("MODE")
                        .value_parser(["none", "sqlite", "mysql"])
                        .help("Requested persistence mode (mysql requires --runtime-profile process or fetch-js)"),
                )
                .arg(
                    Arg::new("private")
                        .long("private")
                        .action(clap::ArgAction::SetTrue)
                        .help("Make the app private before initialization, so only you and its publishers can open it until you share it"),
                ),
        ))
        // Older skills call `handoff`; it prints exactly what `get` prints.
        .subcommand(control_plane_args(app_get_command("handoff").hide(true)))
        .subcommand(control_plane_args(
            Command::new("initialize")
                .about("Initialize or repair an existing app stack and persistence")
                .long_about("Inspect an existing app, plan its requested settings, and initialize \
                    that exact app without reserving another identity. Use for initialization \
                    recovery or an explicitly requested persistence update. MySQL requires \
                    --runtime-profile process or fetch-js. This does not migrate database engines or reclaim deleted apps.")
                .arg(Arg::new("app-id").value_name("APP_ID").required(true)
                    .help("Exact existing app identifier returned by list, get, or create"))
                .arg(Arg::new("environment").long("environment").value_name("ENVIRONMENT")
                    .help("Optional Compose environment override"))
                .arg(Arg::new("runtime-profile").long("runtime-profile").value_name("PROFILE")
                    .help("Requested runtime profile; existing apps retain their deployed profile"))
                .arg(Arg::new("persistence").long("persistence").value_name("MODE")
                    .value_parser(["none", "sqlite", "mysql"])
                    .help("Requested persistence mode; database engine migration is unsupported")),
        ))
        .subcommand(control_plane_args(
            Command::new("deploy")
                .about("Deploy a prebuilt app artifact")
                .long_about(
                    "Upload a prebuilt Hot Pod artifact.tar.gz to Apps Platform. The response \
                     includes the deployed URL and control-plane readiness and diagnostics endpoints.",
                )
                .arg(
                    Arg::new("app-id")
                        .value_name("APP_ID")
                        .required(true)
                        .help("App identifier returned by `bl apps create`"),
                )
                .arg(
                    Arg::new("artifact")
                        .value_name("ARTIFACT_TAR_GZ")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Path to the prebuilt artifact.tar.gz"),
                )
                .arg(
                    Arg::new("environment")
                        .long("environment")
                        .value_name("ENVIRONMENT")
                        .help("Optional Compose environment override"),
                )
                .arg(
                    Arg::new("version-id")
                        .long("version-id")
                        .value_name("VERSION_ID")
                        .help("Optional idempotent version identifier"),
                )
                .arg(
                    Arg::new("deployment-id")
                        .long("deployment-id")
                        .value_name("DEPLOYMENT_ID")
                        .help("Optional deployment identifier"),
                ),
        ))
        .subcommand(control_plane_args(
            Command::new("rollback")
                .about("Roll back an app to a previous or selected version")
                .long_about(
                    "Request one Apps Platform rollback. Omit --version-id to select the previous \
                     active version, or pass an uploaded version explicitly. The response preserves \
                     the control-plane rollback, readiness, and next-call fields without hidden polling.",
                )
                .arg(
                    Arg::new("app-id")
                        .value_name("APP_ID")
                        .required(true)
                        .help("App identifier returned by `bl apps list` or `bl apps create`"),
                )
                .arg(
                    Arg::new("environment")
                        .long("environment")
                        .value_name("ENVIRONMENT")
                        .help("Optional Compose environment override"),
                )
                .arg(
                    Arg::new("version-id")
                        .long("version-id")
                        .value_name("VERSION_ID")
                        .help("Uploaded version to activate; omit to select the previous version"),
                ),
        ))
        .subcommand(control_plane_args(
            Command::new("delete")
                .about("Logically delete an app and retire its active route")
                .long_about(
                    "Request one owner-only Apps Platform logical deletion. The active route is \
                     retired while artifacts may be retained. Capacity remains held when \
                     quota_cleanup_pending is true; explicitly retry cleanup and verify \
                     authoritative usage instead of subtracting a slot locally. \
                     --confirm-app-id and --confirm-environment must exactly match APP_ID and \
                     --environment. After deletion or an uncertain result, inspect the same \
                     app/environment and refresh `bl apps list --scope owned --include-deleted` \
                     before explicitly retrying creation. Owner reconciliation may temporarily \
                     block deletion; read-only inspection remains available.",
                )
                .arg(
                    Arg::new("app-id")
                        .value_name("APP_ID")
                        .required(true)
                        .help("App identifier returned by `bl apps list` or `bl apps create`"),
                )
                .arg(
                    Arg::new("confirm-app-id")
                        .long("confirm-app-id")
                        .value_name("APP_ID")
                        .required(true)
                        .help("Repeat the exact app identifier to confirm logical deletion"),
                )
                .arg(
                    Arg::new("environment")
                        .long("environment")
                        .value_name("ENVIRONMENT")
                        .required(true)
                        .help("Exact Compose environment containing the app"),
                )
                .arg(
                    Arg::new("confirm-environment")
                        .long("confirm-environment")
                        .value_name("ENVIRONMENT")
                        .required(true)
                        .help("Repeat the exact environment to confirm logical deletion"),
                ),
        ))
        .subcommand(control_plane_args(
            Command::new("ready")
                .about("Check readiness for an exact deployed app version")
                .long_about(
                    "Request one control-plane readiness snapshot for an exact deployed app version. \
                     The response includes active-route, runner, readiness, and diagnostic fields; \
                     callers can follow the returned guidance to poll again.",
                )
                .arg(
                    Arg::new("app-id")
                        .value_name("APP_ID")
                        .required(true)
                        .help("App identifier returned by `bl apps create`"),
                )
                .arg(
                    Arg::new("version-id")
                        .long("version-id")
                        .value_name("VERSION_ID")
                        .required(true)
                        .help("Exact version identifier returned by `bl apps deploy`"),
                )
                .arg(
                    Arg::new("environment")
                        .long("environment")
                        .value_name("ENVIRONMENT")
                        .help("Optional Compose environment override"),
                ),
        ))
        .subcommand(control_plane_args(
            Command::new("debug")
                .about("Collect a bounded diagnostic snapshot for an app")
                .long_about(
                    "Request one control-plane diagnostic snapshot, preserving partial results when \
                     individual collectors fail. Optionally correlate the snapshot to a deployed \
                     version and control the number of log lines collected per container.",
                )
                .arg(
                    Arg::new("app-id")
                        .value_name("APP_ID")
                        .required(true)
                        .help("App identifier returned by `bl apps create`"),
                )
                .arg(
                    Arg::new("version-id")
                        .long("version-id")
                        .value_name("VERSION_ID")
                        .help("Optional version identifier to correlate with the active route"),
                )
                .arg(
                    Arg::new("environment")
                        .long("environment")
                        .value_name("ENVIRONMENT")
                        .help("Optional Compose environment override"),
                )
                .arg(
                    Arg::new("tail-lines")
                        .long("tail-lines")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u16).range(1..=MAX_DEBUG_TAIL_LINES.into()))
                        .help("Log lines to collect per container (1-1000; control-plane default: 200)"),
                ),
        ))
        .subcommand(
            Command::new("access")
                .about("Read an app's stored access policy")
                .long_about(
                    "Read the access policy behind `bl apps get`, as Apps Platform stores it. \
                     Visibility `organization` means everyone in the app's workspace and \
                     `restricted` means private. To change who can open an app, use \
                     `bl apps visibility` or `bl apps community`. Approved publishers may read \
                     access settings.",
                )
                .subcommand_required(true)
                .arg_required_else_help(true)
                .disable_help_subcommand(true)
                .subcommand(control_plane_args(
                    Command::new("get")
                        .about("Get an app's current visibility and viewer access")
                        .arg(
                            Arg::new("app-id")
                                .value_name("APP_ID")
                                .required(true)
                                .help("App identifier returned by `bl apps list` or `bl apps create`"),
                        )
                        .arg(
                            Arg::new("environment")
                                .long("environment")
                                .value_name("ENVIRONMENT")
                                .help("Optional Compose environment override"),
                        ),
                ))
                // Replaced by `bl apps visibility`, which keeps community grants
                // and existing viewers. Hidden, not removed, for older scripts.
                .subcommand(control_plane_args(
                    Command::new("set")
                        .hide(true)
                        .about("Replace an app's visibility and explicit viewer list")
                        .long_about(
                            "Replace an app's complete access policy. For restricted visibility, \
                             repeat --viewer for each explicit viewer, or pass --clear-viewers to \
                             explicitly clear the list. The owner and approved publishers remain \
                             effective viewers. Only the original owner may update access. Ask each \
                             intended viewer to copy the exact caller value from `bl apps list --json`.",
                        )
                        .arg(
                            Arg::new("app-id")
                                .value_name("APP_ID")
                                .required(true)
                                .help("App identifier returned by `bl apps list` or `bl apps create`"),
                        )
                        .arg(
                            Arg::new("visibility")
                                .long("visibility")
                                .value_name("VISIBILITY")
                                .value_parser(["organization", "restricted"])
                                .required(true)
                                .help("Who may view the app"),
                        )
                        .arg(
                            Arg::new("viewer")
                                .long("viewer")
                                .value_name("IDENTITY")
                                .action(clap::ArgAction::Append)
                                .help(
                                    "Exact case-sensitive Apps Platform user subject (for example, \
                                     auth0|...); ask the viewer to copy `caller` from `bl apps list \
                                     --json`; repeat for each viewer",
                                ),
                        )
                        .arg(
                            Arg::new("clear-viewers")
                                .long("clear-viewers")
                                .action(clap::ArgAction::SetTrue)
                                .conflicts_with("viewer")
                                .help(
                                    "Confirm replacing the explicit viewer list with an empty list",
                                ),
                        )
                        .arg(
                            Arg::new("environment")
                                .long("environment")
                                .value_name("ENVIRONMENT")
                                .help("Optional Compose environment override"),
                        ),
                )),
        )
        .subcommand(
            Command::new("community")
                .about("Share an app with a Buzz community")
                .long_about(
                    "Grant or revoke viewing access for current members of a Buzz community. \
                     The app owner must be a current member of the community to grant access, but can revoke after leaving it. \
                     A grant adds viewers and never changes the app's visibility. Community viewers can view the app \
                     but cannot use its hosted tools. Use `bl apps get` to see who can open the app afterwards. \
                     `bl apps community list` shows the communities you can share with. Granting and revoking \
                     don't work from a Blox workstation yet; use Share & manage in the BuilderLab portal there.",
                )
                .subcommand_required(true)
                .arg_required_else_help(true)
                .disable_help_subcommand(true)
                .subcommand(community_action_command("grant"))
                .subcommand(community_action_command("revoke"))
                .subcommand(
                    Command::new("list")
                        .about("List the Buzz communities you can share an app with")
                        .long_about(
                            "List the Buzz communities your linked Buzz identity has joined, with the \
                             COMMUNITY_ID that `bl apps community grant` takes. Needs `bl auth login`.",
                        ),
                ),
        )
        .subcommand(control_plane_args(
            Command::new("visibility")
                .about("Switch an app between its workspace and private audiences")
                .long_about(
                    "Choose who can open an app. `workspace` lets everyone in the app's workspace \
                     open it. `private` limits it to you and its publishers. Buzz communities you \
                     shared it with keep access either way, so switching back and forth loses \
                     nothing. Only the app's owner may change this. Prints who can open the app \
                     afterwards.",
                )
                .arg(
                    Arg::new("app-id")
                        .value_name("APP_ID")
                        .required(true)
                        .help("App identifier returned by `bl apps list` or `bl apps create`"),
                )
                .arg(
                    Arg::new("audience")
                        .value_name("AUDIENCE")
                        .value_parser(["workspace", "private"])
                        .required(true)
                        .help("`workspace` for everyone in the app's workspace, `private` for only you"),
                )
                .arg(
                    Arg::new("environment")
                        .long("environment")
                        .value_name("ENVIRONMENT")
                        .help("Optional Compose environment override"),
                ),
        ))
}

fn app_get_command(name: &'static str) -> Command {
    Command::new(name)
        .about("Show an app, who can open it, and its Share & manage link")
        .long_about(
            "Show an app and who can open it, without changing anything. The audience is read \
             from the app's access policy; if that read fails, it is reported as unknown rather \
             than guessed. To also print the Share & manage link, pass the portal origin for \
             the same environment with --management-base-url or BL_APPS_MANAGEMENT_BASE_URL. \
             Add --json for every field, including recorded versions. Whether a recipient's \
             browser can open the app is not checked.",
        )
        .arg(
            Arg::new("app-id")
                .value_name("APP_ID")
                .required(true)
                .help("App identifier returned by `bl apps list` or `bl apps create`"),
        )
        .arg(
            Arg::new("environment")
                .long("environment")
                .value_name("ENVIRONMENT")
                .help("Optional Compose environment override"),
        )
        .arg(
            Arg::new("management-base-url")
                .long("management-base-url")
                .value_name("HTTPS_PORTAL_ORIGIN")
                .help("BuilderLab portal origin used to build the Share & manage link"),
        )
}

fn community_action_command(action: &'static str) -> Command {
    control_plane_args(
        Command::new(action)
            .about(if action == "grant" {
                "Let current members of a Buzz community view an app"
            } else {
                "Remove a Buzz community's viewing access to an app"
            })
            .arg(
                Arg::new("app-id")
                    .value_name("APP_ID")
                    .required(true)
                    .help("App identifier returned by `bl apps list` or `bl apps create`"),
            )
            .arg(
                Arg::new("community-id")
                    .value_name("COMMUNITY_ID")
                    .required(true)
                    .help("Buzz community ID, as listed by `bl apps community list`"),
            ),
    )
}

fn control_plane_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("apps-base-url")
                .long("base-url")
                .visible_alias("control-plane-url")
                .value_name("URL")
                .env(APPS_BASE_URL_ENV_VAR)
                .required(true)
                .help(
                    "Approved BuilderLab Compose control-plane URL (set by the operator on Blox)",
                ),
        )
        .arg(
            Arg::new("apps-client-version")
                .long("client-version")
                .value_name("VERSION")
                .env(APPS_CLIENT_VERSION_ENV_VAR)
                .default_value(APPS_PROTOCOL_VERSION)
                .help("Apps protocol compatibility version sent to the Compose control plane"),
        )
}

pub fn describe_commands() -> Value {
    super::description::describe_command_tree(&command())
}

pub fn run(matches: &ArgMatches) -> Result<()> {
    runner::run(matches, dispatch)
}

fn dispatch(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    if !uses_proxy_auth(matches) {
        runner::ensure_org_configured(config)?;
    }
    match matches.subcommand() {
        Some(("contract", contract_matches)) => run_contract(config, contract_matches),
        Some(("list", list_matches)) => run_list(config, list_matches),
        Some(("get", get_matches)) => run_get(config, get_matches),
        Some(("handoff", handoff_matches)) => run_get(config, handoff_matches),
        Some(("versions", versions_matches)) => run_versions(config, versions_matches),
        Some(("create", create_matches)) => run_create(config, create_matches),
        Some(("initialize", initialize_matches)) => run_initialize(config, initialize_matches),
        Some(("deploy", deploy_matches)) => run_deploy(config, deploy_matches),
        Some(("rollback", rollback_matches)) => run_rollback(config, rollback_matches),
        Some(("delete", delete_matches)) => run_delete(config, delete_matches),
        Some(("ready", ready_matches)) => run_ready(config, ready_matches),
        Some(("debug", debug_matches)) => run_debug(config, debug_matches),
        Some(("access", access_matches)) => run_access(config, access_matches),
        Some(("community", community_matches)) => run_community(config, community_matches),
        Some(("visibility", visibility_matches)) => run_visibility(config, visibility_matches),
        _ => anyhow::bail!("expected an apps subcommand"),
    }
}

fn run_contract(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let base_url = matches
        .get_one::<String>("apps-base-url")
        .context("expected Apps Platform control-plane URL")?;
    let client_version = matches
        .get_one::<String>("apps-client-version")
        .context("expected Apps Platform client version")?;

    let client = ControlPlaneClient::new(base_url, client_version, config.style)?;
    let credential = ComposeSessionCredential::from_config(config, base_url)?;
    let contract = client.contract(&credential)?;
    print_json(&contract)
}

fn run_list(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let scope = matches.get_one::<String>("scope").map(String::as_str);
    let include_deleted = matches.get_flag("include-deleted");
    let (client, credential) = control_plane_context(config, matches)?;
    let response = client.list_apps(&credential, scope, include_deleted)?;
    print_json(&response)
}

fn run_get(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let flag = matches.get_one::<String>("management-base-url");
    let flag_given = flag.is_some_and(|value| !value.trim().is_empty());
    // A bad --management-base-url is a typo in this command, so it fails before
    // any request. A bad environment value is often stale machine setup, so it
    // only costs the link.
    let (portal, portal_problem) = match configured_management_portal(flag) {
        Ok(portal) => (portal, None),
        Err(_) if !flag_given => (None, Some(UNUSABLE_MANAGEMENT_BASE_URL)),
        Err(error) => return Err(error),
    };
    let app_id = matches
        .get_one::<String>("app-id")
        .context("expected app id")?;
    let environment = matches.get_one::<String>("environment").map(String::as_str);
    let (client, credential) = control_plane_context(config, matches)?;
    let inspection = client.get_app(&credential, app_id, environment)?;
    // A policy-read failure must not turn a successful deployment into a false private/shared claim.
    let access = client.get_access(&credential, app_id, environment);
    let mut handoff = build_app_handoff(app_id, portal.as_ref(), &inspection, access.as_ref())?;
    if let (Some(problem), Some(Value::String(next_action))) =
        (portal_problem, handoff.get_mut("next_action"))
    {
        next_action.push(' ');
        next_action.push_str(problem);
    }
    if config.json {
        return print_json(&with_handoff(inspection, handoff));
    }
    let names = community_names(
        config,
        handoff["audience"]["policy"].get("shared_community_ids"),
    );
    print!("{}", app_summary_text(&inspection, &handoff, &names));
    if let Some(problem) = portal_problem {
        println!("Note: {problem}");
    }
    Ok(())
}

const UNUSABLE_MANAGEMENT_BASE_URL: &str = "BL_APPS_MANAGEMENT_BASE_URL is set but isn't an HTTPS portal origin, so the Share & manage link was left out. Fix or unset it.";

/// The inspection fields stay where `get --json` always had them; the handoff
/// fields are added beside them, so `handoff --json` callers keep theirs too.
fn with_handoff(mut inspection: Value, handoff: Value) -> Value {
    if let (Some(fields), Value::Object(handoff)) = (inspection.as_object_mut(), handoff) {
        fields.extend(handoff);
    }
    inspection
}

fn policy_strings<'a>(policy: &'a Value, field: &str) -> Vec<&'a str> {
    policy
        .get(field)
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// One readable answer to "who can open this app?", following the Share &
/// manage dialog: the base audience, then anyone else who can still open a
/// private app, then shared communities. Compose lists the owner among the
/// viewers, drops `effective_viewers` for workspace apps, and leaves out or
/// nulls `shared_community_ids` when there are none; all of that reads the same.
fn who_can_open(
    policy: &Value,
    owner: Option<&str>,
    caller_is_owner: bool,
    community_names: &BTreeMap<String, String>,
) -> String {
    let mut sentences = Vec::new();
    if policy.get("visibility").and_then(Value::as_str) == Some(PRIVATE_VISIBILITY) {
        sentences.push(if caller_is_owner {
            "Only you.".to_string()
        } else {
            "Only the app's owner.".to_string()
        });
        // Without an owner to leave out, a count could include the owner
        // themselves, so say nothing rather than overcount.
        let owner = policy.get("owner").and_then(Value::as_str).or(owner);
        let mut others: Vec<&str> = if owner.is_none() {
            Vec::new()
        } else if policy.get("effective_viewers").is_some() {
            policy_strings(policy, "effective_viewers")
        } else {
            let mut people = policy_strings(policy, "viewers");
            people.extend(policy_strings(policy, "publishers"));
            people
        };
        others.retain(|person| Some(*person) != owner);
        others.sort_unstable();
        others.dedup();
        match others.len() {
            0 => {}
            1 => sentences.push("1 other person can also open it.".to_string()),
            count => sentences.push(format!("{count} other people can also open it.")),
        }
    } else {
        sentences.push("Everyone in the app's workspace.".to_string());
    }
    let communities: Vec<String> = policy_strings(policy, "shared_community_ids")
        .into_iter()
        .map(|id| community_label(id, community_names))
        .collect();
    match communities.as_slice() {
        [] => {}
        [one] => sentences.push(format!("So can members of the Buzz community {one}.")),
        many => sentences.push(format!(
            "So can members of {} Buzz communities: {}.",
            many.len(),
            many.join(", ")
        )),
    }
    sentences.join(" ")
}

fn community_label(id: &str, names: &BTreeMap<String, String>) -> String {
    terminal_safe_text(names.get(id).map_or(id, String::as_str))
}

/// Community names make the summary readable, but they come from Kgoose, not
/// Compose, so any failure (no local login, a Blox workstation) falls back to IDs.
fn community_names(config: &SkillsConfig, ids: Option<&Value>) -> BTreeMap<String, String> {
    // Only decoration: don't hold up the answer for long if Kgoose is slow.
    community_names_with(ids, || {
        joined_communities_for(config, Duration::from_secs(5))
    })
}

/// Asks Kgoose only when there is a community to name.
fn community_names_with(
    ids: Option<&Value>,
    lookup: impl FnOnce() -> Result<Vec<Value>>,
) -> BTreeMap<String, String> {
    if ids.and_then(Value::as_array).is_none_or(Vec::is_empty) {
        return BTreeMap::new();
    }
    lookup()
        .unwrap_or_default()
        .iter()
        .filter_map(|community| {
            Some((
                community.get("community_id")?.as_str()?.to_string(),
                community.get("name")?.as_str()?.to_string(),
            ))
        })
        .collect()
}

fn audience_unknown_text(reason: Option<&str>) -> &'static str {
    match reason {
        Some("unauthenticated") => "Unknown, because your session couldn't be used to read it. Run `bl auth login`, then try again.",
        Some("forbidden") => "Unknown, because this account can't read the app's access. Ask the app's owner.",
        Some("not_found") => "Unknown, because the app's access policy wasn't found.",
        Some("unavailable") => "Unknown, because Apps Platform didn't answer. Try again in a minute.",
        Some("incomplete_policy") => "Unknown, because Apps Platform's answer was incomplete. Try again in a minute.",
        _ => "Unknown, because the request for the app's access failed. Try again in a minute.",
    }
}

fn app_summary_text(
    inspection: &Value,
    handoff: &Value,
    names: &BTreeMap<String, String>,
) -> String {
    let app = &inspection["app"];
    let text = |value: &Value| value.as_str().map(terminal_safe_text);
    let app_id = text(&handoff["app_id"]).unwrap_or_default();
    let mut out = match text(&app["name"]).filter(|name| *name != app_id) {
        Some(name) => format!("{name} ({app_id})\n"),
        None => format!("{app_id}\n"),
    };
    if let Some(url) = text(&handoff["app_url"]) {
        out.push_str(&format!("Open app: {url}\n"));
    }
    let who = match handoff["audience"]["policy"] {
        Value::Null => audience_unknown_text(handoff["audience"]["reason"].as_str()).to_string(),
        ref policy => who_can_open(
            policy,
            app["owner"].as_str(),
            app["role"].as_str() == Some("owner"),
            names,
        ),
    };
    out.push_str(&format!("Who can open it: {who}\n"));
    match text(&handoff["management_url"]) {
        Some(link) => out.push_str(&format!("Share & manage: {link}\n")),
        None => out.push_str(&format!(
            "Share & manage: {}\n",
            share_and_manage_without_portal(&app_id)
        )),
    }
    if let Some(status) = text(&app["status"]) {
        match text(&app["active_version_id"]) {
            Some(version) => out.push_str(&format!("Status: {status}, version {version}\n")),
            None => out.push_str(&format!("Status: {status}\n")),
        }
    }
    out
}

fn management_portal_url(value: &str) -> Result<url::Url> {
    let portal =
        url::Url::parse(value).context("management base URL must be an HTTPS portal origin")?;
    if portal.scheme() != "https"
        || portal.host_str().is_none()
        || !portal.username().is_empty()
        || portal.password().is_some()
        || portal.path() != "/"
        || portal.query().is_some()
        || portal.fragment().is_some()
    {
        anyhow::bail!("management base URL must be an HTTPS portal origin without credentials, a path, query, or fragment");
    }
    Ok(portal)
}

const MANAGEMENT_BASE_URL_ENV_VAR: &str = "BL_APPS_MANAGEMENT_BASE_URL";

/// The portal origin is never inferred from a workstation or app hostname.
/// A blank flag or environment value counts as unset, so an empty export
/// degrades to the no-link handoff instead of failing it.
fn configured_management_portal(flag: Option<&String>) -> Result<Option<url::Url>> {
    let present = |value: &String| !value.trim().is_empty();
    if let Some(flag) = flag.filter(|value| present(value)) {
        return management_portal_url(flag).map(Some);
    }
    std::env::var(MANAGEMENT_BASE_URL_ENV_VAR)
        .ok()
        .filter(present)
        .map(|configured| {
            management_portal_url(&configured)
                .map_err(|error| anyhow::anyhow!("{MANAGEMENT_BASE_URL_ENV_VAR}: {error:#}"))
        })
        .transpose()
}

/// Where an owner finds Share & manage when this machine has no portal origin.
fn share_and_manage_without_portal(app_id: &str) -> String {
    format!("Open Hosted Apps in the BuilderLab portal and use Share & manage on {app_id}.")
}

/// Next step for an owner who needs Share & manage for an app. The portal opens
/// an app's dialog only for `app` plus `workspace`, and the community routes
/// never report a workspace, so name the app instead of deep-linking.
fn share_and_manage_step(portal: Option<&url::Url>, app_id: &str) -> String {
    match portal.and_then(|portal| portal.join("/hosted-apps").ok()) {
        Some(link) => format!("Open Share & manage at {link} and choose {app_id}."),
        None => share_and_manage_without_portal(app_id),
    }
}

fn community_share_and_manage_step(app_id: &str) -> String {
    // An unusable origin only drops the link; the failure it decorates stands.
    let portal = configured_management_portal(None).ok().flatten();
    share_and_manage_step(portal.as_ref(), app_id)
}

fn build_app_handoff(
    app_id: &str,
    portal: Option<&url::Url>,
    inspection: &Value,
    access: Result<&Value, &anyhow::Error>,
) -> Result<Value> {
    let app = inspection
        .get("app")
        .context("app inspection did not return app metadata")?;
    require_exact_app_id(
        "handoff",
        app_id,
        required_response_string(app, "app_id", "Apps handoff")?,
    )?;
    // Share & manage opens an app's dialog only with its workspace, so an app
    // reported without one still shows its audience, just without the link.
    let workspace = app.get("workspace_id").and_then(Value::as_str);
    let management = portal
        .zip(workspace)
        .map(|(portal, workspace)| {
            let mut management = portal.join("/hosted-apps")?;
            management
                .query_pairs_mut()
                .append_pair("app", app_id)
                .append_pair("workspace", workspace);
            Ok::<_, anyhow::Error>(management.to_string())
        })
        .transpose()?;
    let host = app.get("host").and_then(Value::as_str);
    let app_url = host.and_then(|host| {
        let candidate = url::Url::parse(&format!("https://{host}/")).ok()?;
        (candidate.host_str() == Some(host)
            && candidate.username().is_empty()
            && candidate.password().is_none()
            && candidate.port().is_none()
            && candidate.path() == "/"
            && candidate.query().is_none()
            && candidate.fragment().is_none())
        .then(|| candidate.to_string())
    });
    let read_failure_reason = access
        .as_ref()
        .err()
        .map(|error| handoff_read_failure_reason(error));
    let verified = access.ok().filter(|policy| {
        let string_array = |field| {
            policy
                .get(field)
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().all(Value::is_string))
        };
        policy.get("ok") == Some(&Value::Bool(true))
            && policy.get("app_id").and_then(Value::as_str) == Some(app_id)
            && matches!(
                policy.get("visibility").and_then(Value::as_str),
                Some("organization" | "restricted")
            )
            // Compose omits an empty community list but always reports its revision.
            && policy.get("community_grant_revision").and_then(Value::as_u64).is_some()
            && string_array("viewers")
            && (policy.get("visibility").and_then(Value::as_str) != Some("restricted")
                || string_array("effective_viewers"))
            && ["shared_community_ids", "effective_viewers", "publishers"].iter()
                .all(|field| policy.get(field).is_none() || string_array(field))
    });
    let reason = verified
        .is_none()
        .then(|| read_failure_reason.unwrap_or("incomplete_policy"));
    let report = match (verified.is_some(), management.is_some()) {
        (true, true) => "Report the current audience beside Open app and Share & manage.",
        (true, false) => "Report the current audience beside Open app.",
        (false, true) => "App access could not be confirmed. Report the audience as unknown and provide Share & manage; do not claim it is private or shared.",
        (false, false) => "App access could not be confirmed. Report the audience as unknown; do not claim it is private or shared.",
    };
    let mut next_action = format!("{report} Copying the link does not change access.");
    if management.is_none() {
        next_action.push_str(&format!(
            " There is no Share & manage link on this machine. Tell the owner: {} To print the link, rerun with --management-base-url <HTTPS_PORTAL_ORIGIN> or set {MANAGEMENT_BASE_URL_ENV_VAR}.",
            share_and_manage_without_portal(app_id)
        ));
    }
    let who = verified.map(|policy| {
        who_can_open(
            policy,
            app.get("owner").and_then(Value::as_str),
            app.get("role").and_then(Value::as_str) == Some("owner"),
            &BTreeMap::new(),
        )
    });
    Ok(json!({
        "ok": true, "app_id": app_id, "app_url": app_url, "management_url": management,
        "workspace_id": workspace, "who_can_open": who,
        "audience": {"status": if verified.is_some() {"verified"} else {"unknown"}, "policy": verified, "reason": reason},
        "next_action": next_action,
        "recipient_browser_access_verified": false
    }))
}

fn handoff_read_failure_reason(error: &anyhow::Error) -> &'static str {
    let failure = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<CliFailure>());
    let status = failure
        .and_then(|failure| failure.details.as_ref())
        .and_then(|details| details.get("http_status"))
        .and_then(Value::as_u64);
    // Stable, bounded reasons only. Do not expose upstream error bodies or
    // authentication recovery instructions in a successful handoff.
    match status {
        Some(401) => "unauthenticated",
        Some(403) => "forbidden",
        Some(404) => "not_found",
        Some(500..=599) => "unavailable",
        _ if failure.is_some_and(|failure| failure.code == "network_error") => "unavailable",
        _ => "request_failed",
    }
}

fn run_versions(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let app_id = matches
        .get_one::<String>("app-id")
        .context("expected app id")?;
    let environment = matches.get_one::<String>("environment").map(String::as_str);
    let (client, credential) = control_plane_context(config, matches)?;
    let response = client.versions(&credential, app_id, environment)?;
    print_json(&response)
}

fn validate_mysql_runtime(matches: &ArgMatches) -> Result<bool> {
    let mysql_requested =
        matches.get_one::<String>("persistence").map(String::as_str) == Some("mysql");
    if mysql_requested
        && !matches!(
            matches
                .get_one::<String>("runtime-profile")
                .map(String::as_str),
            Some("process" | "fetch-js")
        )
    {
        anyhow::bail!("managed MySQL requires --runtime-profile process or fetch-js");
    }
    Ok(mysql_requested)
}

fn run_create(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let mysql_requested = validate_mysql_runtime(matches)?;
    let (client, credential) = control_plane_context(config, matches)?;
    let requested_app_id = matches.get_one::<String>("app-id").map(String::as_str);
    let request = PlanRequest {
        app_id: requested_app_id,
        name: matches.get_one::<String>("name").map(String::as_str),
        environment: matches.get_one::<String>("environment").map(String::as_str),
        runtime_profile: matches
            .get_one::<String>("runtime-profile")
            .map(String::as_str),
        persistence: matches.get_one::<String>("persistence").map(String::as_str),
        client_version: client.client_version_text(),
    };
    let plan = client.plan(&credential, &request)?;
    let app_id = required_response_string(&plan, "app_id", "Apps Platform plan")?.to_string();
    if let Some(requested_app_id) = requested_app_id {
        require_exact_app_id("plan", requested_app_id, &app_id)
            .map_err(|error| correlate_response_error(error, &plan))?;
    }
    let initialize_required = plan
        .pointer("/initialize/required")
        .and_then(Value::as_bool)
        .context(
            "Apps Platform plan response did not include boolean initialize.required; refusing to reserve the app",
        )
        .map_err(|error| correlate_response_error(error, &plan))?;
    let initialize_recommended = plan
        .pointer("/initialize/recommended")
        .and_then(Value::as_bool)
        .context(
            "Apps Platform plan response did not include boolean initialize.recommended; refusing to reserve the app",
        )
        .map_err(|error| correlate_response_error(error, &plan))?;
    let plan_requests_initialize = initialize_required || initialize_recommended;
    if mysql_requested {
        validate_mysql_plan(&plan, request.runtime_profile)
            .map_err(|error| correlate_response_error(error, &plan))?;
        if !plan_requests_initialize {
            return Err(correlate_response_error(anyhow::anyhow!("Apps Platform mysql plan must request initialization before deployment; refusing to reserve the app"), &plan));
        }
    }
    let mutation_request = mutation_request_from_plan(&plan);
    let (reservation, reservation_reconciled) =
        reconcile_create_reservation(&client, &credential, &app_id, &plan, &mutation_request)?;
    // Private is applied before initialization so a private app is never visible.
    let visibility = if matches.get_flag("private") {
        let environment = mutation_request.get("environment").and_then(Value::as_str);
        let response = client
            .set_visibility(&credential, &app_id, PRIVATE_VISIBILITY, environment)
            .and_then(|response| require_visibility(&app_id, PRIVATE_VISIBILITY, response))
            .with_context(|| {
                format!("Apps Platform reserved app_id {app_id:?}, but did not make it private. Do not deploy it. After fixing the error, run `bl apps visibility {app_id} private` or retry the same `bl apps create --private` command.")
            })?;
        Some(response)
    } else {
        None
    };
    let initialize = if plan_requests_initialize {
        let response = client
            .initialize(&credential, &app_id, &mutation_request)
            .with_context(|| {
                if mysql_requested {
                    let profile = request.runtime_profile.expect("validated MySQL runtime");
                    format!("Apps Platform reserved app_id {app_id:?}, but MySQL initialization did not complete. Inspect it with `bl apps get`, then resume the same app with `bl apps initialize` using the same endpoint, environment, --runtime-profile {profile} and --persistence mysql.")
                } else {
                    format!("Apps Platform reserved app_id {app_id:?}, but initialization did not complete. Retry the same `bl apps create` command to reconcile the reservation and continue initialization.")
                }
            })?;
        let initialized_app_id =
            required_response_string(&response, "app_id", "Apps Platform initialize")?;
        require_exact_app_id("initialize", &app_id, initialized_app_id)
            .map_err(|error| correlate_response_error(error, &response))?;
        confirm_mysql_initialization(&response, mysql_requested)?;
        Some(response)
    } else {
        None
    };
    let effective_external_url = match initialize.as_ref() {
        Some(response) => Value::String(
            required_response_string(response, "external_url", "Apps Platform initialize")?
                .to_string(),
        ),
        None => reservation
            .get("external_url")
            .cloned()
            .unwrap_or(Value::Null),
    };
    print_json(&json!({
        "ok": true,
        "app_id": app_id,
        "external_url": effective_external_url,
        "reserved": true,
        "reservation_reconciled": reservation_reconciled,
        "initialized": initialize.is_some(),
        "plan": plan,
        "reservation": reservation,
        "visibility": visibility,
        "initialize": initialize,
    }))
}

fn validate_mysql_plan(plan: &Value, requested_profile: Option<&str>) -> Result<()> {
    if plan.get("persistence").and_then(Value::as_str) != Some("mysql")
        || plan.get("runtime_profile").and_then(Value::as_str) != requested_profile
    {
        anyhow::bail!("Apps Platform plan did not preserve mysql persistence and the requested runtime; refusing to reserve or initialize the app");
    }
    Ok(())
}

fn confirm_mysql_initialization(response: &Value, mysql_requested: bool) -> Result<()> {
    if mysql_requested && response.get("persistence").and_then(Value::as_str) != Some("mysql") {
        return Err(correlate_response_error(
            anyhow::anyhow!("Apps Platform initialization did not confirm mysql persistence; inspect the app before deploying"), response,
        ));
    }
    Ok(())
}

fn run_initialize(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let mysql_requested = validate_mysql_runtime(matches)?;
    let app_id = matches
        .get_one::<String>("app-id")
        .context("expected app id")?;
    let environment = matches.get_one::<String>("environment").map(String::as_str);
    let (client, credential) = control_plane_context(config, matches)?;
    let existing = client.get_app(&credential, app_id, environment)?;
    let app = existing
        .get("app")
        .context("Apps Platform get response did not include app")?;
    let observed_id = required_response_string(app, "app_id", "Apps Platform get")?;
    require_exact_app_id("get", app_id, observed_id)
        .map_err(|error| correlate_response_error(error, &existing))?;
    if !value_is_absent_or_empty_text(app.get("deleted_at"))
        || app.get("status").and_then(Value::as_str) == Some("deleted")
    {
        anyhow::bail!(
            "Apps Platform initialize cannot reclaim a deleted app; select an active app"
        );
    }
    let request = PlanRequest {
        app_id: Some(app_id),
        name: None,
        environment,
        runtime_profile: matches
            .get_one::<String>("runtime-profile")
            .map(String::as_str),
        persistence: matches.get_one::<String>("persistence").map(String::as_str),
        client_version: client.client_version_text(),
    };
    let plan = client.plan(&credential, &request)?;
    let planned_id = required_response_string(&plan, "app_id", "Apps Platform plan")?;
    require_exact_app_id("plan", app_id, planned_id)
        .map_err(|error| correlate_response_error(error, &plan))?;
    if mysql_requested {
        validate_mysql_plan(&plan, request.runtime_profile)
            .map_err(|error| correlate_response_error(error, &plan))?;
    }
    let response = client.initialize(&credential, app_id, &mutation_request_from_plan(&plan))?;
    let initialized_id = required_response_string(&response, "app_id", "Apps Platform initialize")?;
    require_exact_app_id("initialize", app_id, initialized_id)
        .map_err(|error| correlate_response_error(error, &response))?;
    confirm_mysql_initialization(&response, mysql_requested)?;
    print_json(&json!({"ok":true, "app_id":app_id, "initialized":true,
        "external_url":response.get("external_url"), "plan":plan, "initialize":response}))
}

fn reconcile_create_reservation(
    client: &ControlPlaneClient,
    credential: &ComposeSessionCredential,
    app_id: &str,
    plan: &Value,
    mutation_request: &Value,
) -> Result<(Value, bool)> {
    match client.reserve(credential, app_id, mutation_request) {
        Ok(reservation) => {
            let reserved_app_id =
                required_response_string(&reservation, "app_id", "Apps Platform reserve")?;
            require_exact_app_id("reserve", app_id, reserved_app_id)
                .map_err(|error| correlate_response_error(error, &reservation))?;
            Ok((reservation, false))
        }
        Err(reserve_error) => {
            let environment = mutation_request.get("environment").and_then(Value::as_str);
            match client.get_app(credential, app_id, environment) {
                Ok(existing)
                    if is_matching_incomplete_reservation(&existing, app_id, mutation_request) =>
                {
                    let mut reservation = json!({
                        "ok": true,
                        "app_id": app_id,
                        "external_url": plan.get("external_url").cloned().unwrap_or(Value::Null),
                        "reconciled": true,
                        "app": existing.get("app").cloned().unwrap_or(Value::Null),
                    });
                    retain_response_trace_id(
                        &mut reservation,
                        response_value_trace_id(&existing).as_deref(),
                    );
                    if let Some(trace_id) = failure_trace_id(&reserve_error) {
                        reservation["reserve_trace_id"] = json!(trace_id);
                    }
                    Ok((reservation, true))
                }
                Ok(existing) if reservation_outcome_is_unknown(&reserve_error) => {
                    let mismatch = correlate_response_error(
                        anyhow::anyhow!(
                            "the inspected app was not the same caller-owned, incomplete reservation"
                        ),
                        &existing,
                    );
                    Err(reservation_outcome_unknown(
                        app_id,
                        environment,
                        &reserve_error,
                        &mismatch,
                    ))
                }
                Ok(_) => Err(reserve_error),
                Err(inspect_error) if reservation_outcome_is_unknown(&reserve_error) => {
                    Err(reservation_outcome_unknown(
                        app_id,
                        environment,
                        &reserve_error,
                        &inspect_error,
                    ))
                }
                Err(_) => Err(reserve_error),
            }
        }
    }
}

fn is_matching_incomplete_reservation(
    response: &Value,
    app_id: &str,
    mutation_request: &Value,
) -> bool {
    let Some(app) = response.get("app").and_then(Value::as_object) else {
        return false;
    };
    if response.get("ok").and_then(Value::as_bool) != Some(true)
        || response
            .get("versions")
            .and_then(Value::as_array)
            .is_none_or(|versions| !versions.is_empty())
        || app.get("app_id").and_then(Value::as_str) != Some(app_id)
        || app.get("role").and_then(Value::as_str) != Some("owner")
        || app.get("route_status").and_then(Value::as_str) != Some("idle")
        || app.get("route_revision").and_then(Value::as_u64) != Some(1)
        || !value_is_absent_or_empty_text(app.get("active_version_id"))
        || !value_is_absent_or_empty_text(app.get("version_id"))
        || !value_is_absent_or_empty_text(app.get("deleted_at"))
    {
        return false;
    }
    [
        ("environment", "environment"),
        ("persistence", "persistence"),
        ("runtime_class", "runtime_class"),
        ("runtime_profile", "runtime_profile"),
        ("name", "name"),
    ]
    .into_iter()
    .all(|(request_field, app_field)| {
        mutation_request
            .get(request_field)
            .and_then(Value::as_str)
            .is_none_or(|expected| app.get(app_field).and_then(Value::as_str) == Some(expected))
    })
}

fn value_is_absent_or_empty_text(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        Some(_) => false,
    }
}

fn reservation_outcome_is_unknown(error: &anyhow::Error) -> bool {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<CliFailure>())
        .is_none_or(|failure| failure.code == "network_error")
}

fn reservation_outcome_unknown(
    app_id: &str,
    environment: Option<&str>,
    reserve_error: &anyhow::Error,
    inspect_error: &anyhow::Error,
) -> anyhow::Error {
    let environment_argument = environment
        .map(|value| format!(" --environment {value}"))
        .unwrap_or_default();
    let error = failure(
        exit_codes::NETWORK,
        "reservation_outcome_unknown",
        format!(
            "Apps Platform may have reserved app_id {app_id:?}, but the CLI did not receive a complete reservation result and could not verify the app.\n\
             reserve_error: {reserve_error:#}\n\
             inspection_error: {inspect_error:#}\n\
             next_action: Run `bl apps get {app_id}{environment_argument}`. If it reports a caller-owned app with route_status `idle`, retry the same `bl apps create` command; the retry will reconcile that reservation and continue initialization."
        ),
    );
    with_failure_trace_id(
        error,
        failure_trace_id(reserve_error).or_else(|| failure_trace_id(inspect_error)),
    )
}

fn require_exact_app_id(stage: &str, expected: &str, actual: &str) -> Result<()> {
    if actual != expected {
        anyhow::bail!(
            "Apps Platform {stage} returned app_id {actual:?}; expected exact app_id {expected:?}. No replacement app was accepted."
        );
    }
    Ok(())
}

fn run_deploy(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let artifact = matches
        .get_one::<PathBuf>("artifact")
        .context("expected artifact.tar.gz path")?;
    validate_artifact_path(artifact)?;
    let app_id = matches
        .get_one::<String>("app-id")
        .context("expected app id")?;
    let options = DeployOptions {
        environment: matches.get_one::<String>("environment").cloned(),
        version_id: matches.get_one::<String>("version-id").cloned(),
        deployment_id: matches.get_one::<String>("deployment-id").cloned(),
    };
    let (client, credential) = control_plane_context(config, matches)?;
    let response = client.deploy(&credential, app_id, artifact, &options)?;
    print_json(&response)
}

fn run_rollback(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let app_id = matches
        .get_one::<String>("app-id")
        .context("expected app id")?;
    let request = RollbackRequest {
        environment: matches.get_one::<String>("environment").map(String::as_str),
        version_id: matches.get_one::<String>("version-id").map(String::as_str),
    };
    let (client, credential) = control_plane_context(config, matches)?;
    let response = client.rollback(&credential, app_id, &request)?;
    print_json(&response)
}

fn run_delete(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let app_id = matches
        .get_one::<String>("app-id")
        .context("expected app id")?;
    let confirm_app_id = matches
        .get_one::<String>("confirm-app-id")
        .context("expected delete confirmation app id")?;
    let environment = matches
        .get_one::<String>("environment")
        .context("expected delete environment")?;
    let confirm_environment = matches
        .get_one::<String>("confirm-environment")
        .context("expected delete confirmation environment")?;
    validate_delete_confirmation(app_id, environment, confirm_app_id, confirm_environment)?;
    let request = DeleteAppRequest { environment };
    let (client, credential) = control_plane_context(config, matches)?;
    let response = client.delete_app(&credential, app_id, &request)?;
    print_json(&response)
}

fn validate_delete_confirmation(
    app_id: &str,
    environment: &str,
    confirm_app_id: &str,
    confirm_environment: &str,
) -> Result<()> {
    if confirm_app_id != app_id {
        anyhow::bail!("delete requires --confirm-app-id to exactly match APP_ID ({app_id})");
    }
    if confirm_environment != environment {
        anyhow::bail!(
            "delete requires --confirm-environment to exactly match --environment ({environment})"
        );
    }
    Ok(())
}

fn run_ready(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let app_id = matches
        .get_one::<String>("app-id")
        .context("expected app id")?;
    let version_id = matches
        .get_one::<String>("version-id")
        .context("expected version id")?;
    let environment = matches.get_one::<String>("environment").map(String::as_str);
    let (client, credential) = control_plane_context(config, matches)?;
    let response = client.ready(&credential, app_id, version_id, environment)?;
    print_json(&response)
}

fn run_debug(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let app_id = matches
        .get_one::<String>("app-id")
        .context("expected app id")?;
    let environment = matches.get_one::<String>("environment").map(String::as_str);
    let version_id = matches.get_one::<String>("version-id").map(String::as_str);
    let tail_lines = matches.get_one::<u16>("tail-lines").copied();
    let (client, credential) = control_plane_context(config, matches)?;
    let response = client.debug(&credential, app_id, environment, version_id, tail_lines)?;
    print_json(&response)
}

fn run_community(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let (action, action_matches) = matches
        .subcommand()
        .context("expected community grant, revoke or list")?;
    if action == "list" {
        return run_community_list(config);
    }
    let app_id = action_matches
        .get_one::<String>("app-id")
        .context("expected app id")?;
    let community_id = action_matches
        .get_one::<String>("community-id")
        .context("expected community id")?;
    let base_url = action_matches
        .get_one::<String>("apps-base-url")
        .context("expected Apps Platform control-plane URL")?;
    // The Blox proxy only asks Kgoose for a sharing credential on workspace
    // routes, so Compose would refuse every community request it forwards.
    if proxy_auth_for_url(base_url) {
        let next_action = format!(
            "{} Or run `bl apps community` with `--base-url` set to an approved BuilderLab ingress after `bl auth login`.",
            community_share_and_manage_step(app_id)
        );
        let mut error = CliFailure::new(
            exit_codes::GENERAL,
            "community_sharing_unavailable_through_proxy",
            format!(
                "Community sharing isn't available through the Blox workstation proxy yet.\nnext_action: {next_action}"
            ),
        );
        error.next_action = Some(json!(next_action));
        return Err(anyhow::Error::new(error));
    }
    let (client, credential) = control_plane_context(config, action_matches)?;
    // Kgoose replaces the session with a credential bound to the owner, app and
    // community, and checks current community membership before a grant. Read
    // only the CAS inputs on that same route; Compose rechecks ownership and the
    // revision when applying the change.
    let current = client
        .get_community_grant_revision(&credential, app_id, community_id)
        .map_err(|error| with_missing_lifecycle_step(error, app_id))?;
    let lifecycle_id = current
        .get("lifecycle_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            let next_action = missing_lifecycle_step(app_id);
            let mut error = CliFailure::new(
                exit_codes::GENERAL,
                "app_sharing_lifecycle_missing",
                format!("app has no active sharing lifecycle\nnext_action: {next_action}"),
            );
            error.next_action = Some(json!(next_action));
            correlate_response_error(anyhow::Error::new(error), &current)
        })?;
    let expected_revision = current
        .get("community_grant_revision")
        .and_then(Value::as_u64)
        .context("app sharing response has no community grant revision")
        .map_err(|error| correlate_response_error(error, &current))?;
    let response = client.update_community_grant(
        &credential,
        app_id,
        community_id,
        lifecycle_id,
        action,
        expected_revision,
    )?;
    if config.json {
        return print_json(&response);
    }
    let names = community_names(config, Some(&json!([community_id])));
    print!(
        "{}",
        community_change_text(app_id, community_id, action, &response, &names)
    );
    Ok(())
}

fn community_change_text(
    app_id: &str,
    community_id: &str,
    action: &str,
    response: &Value,
    names: &BTreeMap<String, String>,
) -> String {
    let app = terminal_safe_text(app_id);
    let community = community_label(community_id, names);
    let listed = policy_strings(response, "shared_community_ids").contains(&community_id);
    let summary = match (action, listed) {
        ("grant", true) => format!(
            "Members of the Buzz community {community} can open {app} now, whatever its visibility."
        ),
        ("revoke", false) => {
            format!("{app} is no longer shared with the Buzz community {community}.")
        }
        // Report what the server said rather than what was asked for.
        (_, true) => format!("{app} is still shared with the Buzz community {community}."),
        (_, false) => format!("{app} isn't shared with the Buzz community {community}."),
    };
    format!("{summary}\nRun `bl apps get {app}` to see everyone who can open it.\n")
}

/// Compose sets an app's sharing lifecycle when it reserves, initializes or
/// deploys it, so an app without one needs a deployment before any grant.
fn missing_lifecycle_step(app_id: &str) -> String {
    format!("{app_id} has no sharing lifecycle yet. Deploy it with `bl apps deploy`, then retry.")
}

/// The grant read answers 409 `community_grant_conflict` only when the app has
/// no sharing lifecycle. Add the recovery step the server leaves out.
fn with_missing_lifecycle_step(mut error: anyhow::Error, app_id: &str) -> anyhow::Error {
    if let Some(failure) = error.downcast_mut::<CliFailure>() {
        let conflict = failure.code == "community_grant_conflict"
            && failure
                .details
                .as_ref()
                .and_then(|details| details.get("http_status"))
                .and_then(Value::as_u64)
                == Some(409);
        if conflict && failure.next_action.is_none() {
            let next_action = missing_lifecycle_step(app_id);
            failure.message.push_str("\nnext_action: ");
            failure.message.push_str(&next_action);
            failure.next_action = Some(json!(next_action));
        }
    }
    error
}

const JOINED_COMMUNITIES_PATH: &str = "/v1/buzz/joined-communities/list";

/// Kgoose resolves the caller's linked Buzz identity and asks the relay which
/// communities it has joined, the same list Share & manage offers.
fn run_community_list(config: &SkillsConfig) -> Result<()> {
    let communities = joined_communities_for(config, Duration::from_secs(30))?;
    if config.json {
        return print_json(&json!({"ok": true, "communities": communities}));
    }
    print!("{}", joined_communities_text(&communities));
    Ok(())
}

fn joined_communities_for(config: &SkillsConfig, timeout: Duration) -> Result<Vec<Value>> {
    let storage = default_session_storage(config)?;
    let session = storage
        .get(&session_storage_key_from_config(config))?
        .and_then(|credential| credential.session_credential_header_value())
        .ok_or_else(auth_required_error)?;
    let service_url = kgoose_service_url(&config.kgoose_base_url, &config.kgoose_service_path);
    let url = auth_url(&service_url, JOINED_COMMUNITIES_PATH)?;
    let mut request = build_auth_http_client(timeout)?
        .post(url)
        .header(USER_AGENT, CLI_USER_AGENT)
        .header(ACCEPT, "application/json")
        .header(SESSION_CREDENTIAL_HEADER, &session)
        .json(&json!({}));
    if let Some(baggage) = playpen_baggage(config.playpen.as_deref()) {
        request = request.header("Baggage", baggage);
    }
    let response = request
        .send()
        .map_err(|error| network_failure("POST", JOINED_COMMUNITIES_PATH, error))?;
    let status = response.status();
    let body = response
        .text()
        .with_context(|| format!("read {JOINED_COMMUNITIES_PATH} response"))?
        .replace(&session, "[REDACTED]");
    joined_communities(status, &body)
}

fn joined_communities(status: StatusCode, body: &str) -> Result<Vec<Value>> {
    if status == StatusCode::UNAUTHORIZED {
        return Err(auth_required_error());
    }
    let parsed: Option<Value> = serde_json::from_str(body).ok();
    let error = parsed
        .as_ref()
        .and_then(|value| value.get("error"))
        .filter(|error| !error.is_null());
    // Kgoose writes this proto with Wire JSON, which leaves an empty list out,
    // so `{}` means no communities. Anything that isn't a JSON object, or whose
    // `communities` isn't a list, is some other page and must not read as none.
    let shape_ok = parsed.as_ref().is_some_and(|value| {
        value.is_object()
            && value
                .get("communities")
                .is_none_or(|communities| communities.is_array())
    });
    if !status.is_success() || error.is_some() || !shape_ok {
        // Only a stable identifier is kept from the server; its message and
        // body can be anything, such as an HTML error page.
        let code = error
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str)
            .filter(|code| {
                !code.is_empty()
                    && code.len() <= 64
                    && code.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            })
            .unwrap_or(if status.is_success() {
                "community_list_invalid_response"
            } else {
                "community_list_failed"
            });
        let (explanation, next_action) = match (code, status.as_u16()) {
            ("missing_mapping", _) => (
                "Your BuilderLab account isn't linked to a Buzz identity yet.",
                "Connect your Buzz identity on the Buzz page of the BuilderLab portal, then retry.",
            ),
            (_, 403) => (
                "This account can't list Buzz communities.",
                "Run `bl auth login` with the account you use in Buzz, then retry.",
            ),
            (_, 500..) => (
                "Kgoose couldn't list your Buzz communities right now.",
                "Wait a minute, then try again.",
            ),
            _ => (
                "Kgoose didn't return a usable list of your Buzz communities.",
                "Try again. If it keeps happening, use Share & manage in the BuilderLab portal.",
            ),
        };
        let mut failure = CliFailure::new(
            match status.as_u16() {
                403 => exit_codes::FORBIDDEN,
                500.. => exit_codes::NETWORK,
                _ => exit_codes::GENERAL,
            },
            code,
            format!(
                "POST {JOINED_COMMUNITIES_PATH} failed with {} ({code})\n{explanation}\nnext_action: {next_action}",
                status.as_u16()
            ),
        );
        failure.details = Some(json!({"http_status": status.as_u16()}));
        failure.next_action = Some(json!(next_action));
        let correlation = parsed
            .as_ref()
            .and_then(|value| {
                value
                    .get("correlation_id")
                    .or_else(|| value.get("correlationId"))
            })
            .and_then(Value::as_str)
            .map(terminal_safe_text);
        return Err(with_failure_trace_id(
            anyhow::Error::new(failure),
            correlation.as_deref(),
        ));
    }
    let communities = parsed
        .as_ref()
        .and_then(|value| value.get("communities"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    communities
        .iter()
        .map(|community| {
            let field = |snake: &str, camel: &str| {
                community
                    .get(snake)
                    .or_else(|| community.get(camel))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            };
            let id = field("id", "id").with_context(|| {
                format!("{JOINED_COMMUNITIES_PATH} returned a community without an id")
            })?;
            Ok(json!({
                "community_id": id,
                "name": field("name", "name"),
                "host": field("normalized_host", "normalizedHost"),
            }))
        })
        .collect()
}

fn joined_communities_text(communities: &[Value]) -> String {
    if communities.is_empty() {
        return "You haven't joined any Buzz community yet.\n".to_string();
    }
    let mut text = String::new();
    for community in communities {
        let text_field = |name: &str| {
            community
                .get(name)
                .and_then(Value::as_str)
                .map(terminal_safe_text)
        };
        let id = text_field("community_id").unwrap_or_default();
        match (text_field("name"), text_field("host")) {
            (Some(name), Some(host)) => text.push_str(&format!("{id}  {name} ({host})\n")),
            (Some(name), None) => text.push_str(&format!("{id}  {name}\n")),
            (None, Some(host)) => text.push_str(&format!("{id}  {host}\n")),
            (None, None) => text.push_str(&format!("{id}\n")),
        }
    }
    text.push_str("Share an app with one: bl apps community grant <APP_ID> <COMMUNITY_ID>\n");
    text
}

fn run_access(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("get", get_matches)) => run_access_get(config, get_matches),
        Some(("set", set_matches)) => run_access_set(config, set_matches),
        _ => anyhow::bail!("expected an access subcommand"),
    }
}

fn run_access_get(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let app_id = matches
        .get_one::<String>("app-id")
        .context("expected app id")?;
    let environment = matches.get_one::<String>("environment").map(String::as_str);
    let (client, credential) = control_plane_context(config, matches)?;
    let response = client.get_access(&credential, app_id, environment)?;
    print_json(&response)
}

fn run_access_set(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let app_id = matches
        .get_one::<String>("app-id")
        .context("expected app id")?;
    let visibility = matches
        .get_one::<String>("visibility")
        .context("expected access visibility")?;
    let viewers: Vec<&str> = matches
        .get_many::<String>("viewer")
        .into_iter()
        .flatten()
        .map(String::as_str)
        .collect();
    if visibility == "restricted" && viewers.is_empty() && !matches.get_flag("clear-viewers") {
        anyhow::bail!(
            "restricted visibility requires at least one --viewer or explicit --clear-viewers confirmation"
        );
    }
    let request = AccessRequest {
        visibility,
        viewers,
        environment: matches.get_one::<String>("environment").map(String::as_str),
    };
    let (client, credential) = control_plane_context(config, matches)?;
    let response = client.set_access(&credential, app_id, &request)?;
    print_json(&response)
}

const WORKSPACE_VISIBILITY: &str = "organization";
const PRIVATE_VISIBILITY: &str = "restricted";

fn run_visibility(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let app_id = matches
        .get_one::<String>("app-id")
        .context("expected app id")?;
    let visibility = match matches
        .get_one::<String>("audience")
        .map(String::as_str)
        .context("expected app audience")?
    {
        "workspace" => WORKSPACE_VISIBILITY,
        "private" => PRIVATE_VISIBILITY,
        audience => anyhow::bail!("unknown app audience {audience:?}"),
    };
    let environment = matches.get_one::<String>("environment").map(String::as_str);
    let (client, credential) = control_plane_context(config, matches)?;
    let response = client.set_visibility(&credential, app_id, visibility, environment)?;
    let response = require_visibility(app_id, visibility, response)?;
    if config.json {
        return print_json(&response);
    }
    // Only the owner may change visibility, so the caller is the owner here.
    let names = community_names(config, response.get("shared_community_ids"));
    println!(
        "Who can open {} now: {}",
        terminal_safe_text(app_id),
        who_can_open(&response, None, true, &names)
    );
    Ok(())
}

/// Accepts a visibility response only when it reports the requested app and visibility.
fn require_visibility(app_id: &str, visibility: &str, response: Value) -> Result<Value> {
    let updated_app_id = required_response_string(&response, "app_id", "Apps Platform visibility")?;
    require_exact_app_id("visibility", app_id, updated_app_id)
        .map_err(|error| correlate_response_error(error, &response))?;
    let updated_visibility =
        required_response_string(&response, "visibility", "Apps Platform visibility")?;
    if updated_visibility != visibility {
        return Err(correlate_response_error(
            anyhow::anyhow!(
                "Apps Platform visibility returned {updated_visibility:?}; expected {visibility:?}"
            ),
            &response,
        ));
    }
    Ok(response)
}

fn control_plane_context(
    config: &SkillsConfig,
    matches: &ArgMatches,
) -> Result<(ControlPlaneClient, ComposeSessionCredential)> {
    let base_url = matches
        .get_one::<String>("apps-base-url")
        .context("expected Apps Platform control-plane URL")?;
    let client_version = matches
        .get_one::<String>("apps-client-version")
        .context("expected Apps Platform client version")?;
    let client = ControlPlaneClient::new(base_url, client_version, config.style)?;
    let credential = ComposeSessionCredential::from_config(config, base_url)?;
    Ok((client, credential))
}

#[derive(Serialize)]
struct PlanRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    app_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_profile: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    persistence: Option<&'a str>,
    client_version: &'a str,
}

#[derive(Serialize)]
struct RollbackRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_id: Option<&'a str>,
}

#[derive(Serialize)]
struct DeleteAppRequest<'a> {
    environment: &'a str,
}

#[derive(Serialize)]
struct VisibilityRequest<'a> {
    visibility: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<&'a str>,
}

#[derive(Serialize)]
struct AccessRequest<'a> {
    visibility: &'a str,
    viewers: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<&'a str>,
}

#[derive(Default)]
struct DeployOptions {
    environment: Option<String>,
    version_id: Option<String>,
    deployment_id: Option<String>,
}

fn mutation_request_from_plan(plan: &Value) -> Value {
    let mut request = Map::new();
    for field in [
        "environment",
        "persistence",
        "runtime_class",
        "runtime_profile",
    ] {
        if let Some(value) = plan.get(field).and_then(Value::as_str) {
            if !value.is_empty() {
                request.insert(field.to_string(), Value::String(value.to_string()));
            }
        }
    }
    if let Some(display_name) = plan.get("display_name").and_then(Value::as_str) {
        if !display_name.is_empty() {
            request.insert("name".to_string(), Value::String(display_name.to_string()));
        }
    }
    Value::Object(request)
}

fn required_response_string<'a>(
    value: &'a Value,
    field: &str,
    description: &str,
) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{description} response did not include {field}"))
        .map_err(|error| correlate_response_error(error, value))
}

fn validate_artifact_path(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("read Apps Platform artifact {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!(
            "Apps Platform artifact must be a file containing a prebuilt artifact.tar.gz: {}",
            path.display()
        );
    }
    Ok(())
}

enum ComposeSessionCredential {
    Session {
        authorization: HeaderValue,
        secret: String,
        access_recovery: Option<AppsAccessRecovery>,
    },
    Proxy,
}

impl ComposeSessionCredential {
    fn from_config(config: &SkillsConfig, base_url: &str) -> Result<Self> {
        if proxy_auth_for_url(base_url) {
            return Ok(Self::Proxy);
        }
        let storage = default_session_storage(config)?;
        let verified =
            verify_stored_session(config, storage.as_ref())?.ok_or_else(auth_required_error)?;
        let mut credential = Self::from_stored(verified.credential)?;
        if let Self::Session {
            access_recovery, ..
        } = &mut credential
        {
            *access_recovery =
                AppsAccessRecovery::from_auth_me(&verified.me, &config.kgoose_base_url);
        }
        Ok(credential)
    }

    fn from_stored(credential: StoredSessionCredential) -> Result<Self> {
        let secret = credential
            .session_credential_header_value()
            .ok_or_else(auth_required_error)?;
        Self::new(secret)
    }

    fn new(secret: String) -> Result<Self> {
        // Authorization scheme is a backend contract, independent of CLI branding.
        let authorization = HeaderValue::from_str(&format!("BBIdentity {secret}"))
            .context("stored BuilderLab CLI auth session is invalid; run `bl auth login`")?;
        Ok(Self::Session {
            authorization,
            secret,
            access_recovery: None,
        })
    }

    fn authorization_header(&self) -> Option<HeaderValue> {
        match self {
            Self::Session { authorization, .. } => Some(authorization.clone()),
            Self::Proxy => None,
        }
    }

    fn redact(&self, value: &str) -> String {
        match self {
            Self::Session { secret, .. } => value.replace(secret, "[REDACTED]"),
            Self::Proxy => value.to_string(),
        }
    }

    fn access_recovery(&self) -> Option<&AppsAccessRecovery> {
        match self {
            Self::Session {
                access_recovery, ..
            } => access_recovery.as_ref(),
            Self::Proxy => None,
        }
    }
}

struct AppsAccessRecovery {
    code: &'static str,
    next_action: String,
}

impl AppsAccessRecovery {
    fn from_auth_me(me: &AuthMeResponse, base_url: &str) -> Option<Self> {
        // Use only the coarse, caller-visible status. Pending or unknown status
        // must not be diagnosed from legacy screening fields or product absence.
        if me.account_status.as_deref() == Some("ACCOUNT_STATUS_NEEDS_DETAILS") {
            let destination = account_setup_url(base_url)
                .unwrap_or_else(|| "the BuilderLab web app for this environment".to_string());
            return Some(Self {
                code: "account_setup_required",
                next_action: format!(
                    "Your CLI session is valid, but account setup is incomplete. Finish account setup at {destination} using the same account, then retry this command. Repeating `bl auth login` will not complete account setup."
                ),
            });
        }
        if matches!(
            me.account_status.as_deref(),
            None | Some("ACCOUNT_STATUS_OK")
        ) && me.enabled_products.as_ref().is_some_and(|products| {
            !products
                .iter()
                .any(|product| product == "BUILDERLAB_PRODUCT_BUILDERLAB")
        }) {
            return Some(Self {
                code: "builderlab_access_required",
                next_action: "Your CLI session is valid, but BuilderLab product access is not enabled for this account. Ask your administrator or the BuilderLab team to confirm Apps access for this account and environment, then retry this command.".to_string(),
            });
        }
        None
    }
}

fn account_setup_url(base_url: &str) -> Option<String> {
    let url = url::Url::parse(base_url).ok()?;
    // These app hosts serve the supported /account/setup web route. Do not
    // invent a web route on direct API hosts, proxies, or custom deployments.
    match url.origin().ascii_serialization().as_str() {
        "https://app.builderlab.xyz" => {
            Some("https://app.builderlab.xyz/account/setup".to_string())
        }
        "https://app.builderlabstaging.xyz" => {
            Some("https://app.builderlabstaging.xyz/account/setup".to_string())
        }
        _ => None,
    }
}

struct ControlPlaneClient {
    client: Client,
    #[cfg(test)]
    test_transport: Option<Box<dyn ControlPlaneTransport>>,
    base_url: String,
    client_version: HeaderValue,
    client_version_text: String,
    traceparent: Option<HeaderValue>,
    style: Style,
}

#[cfg(test)]
trait ControlPlaneTransport {
    fn execute(&self, request: Request) -> reqwest::Result<Response>;
}

#[cfg(test)]
struct LoopbackTestTransport {
    client: Client,
    base_url: url::Url,
}

#[cfg(test)]
impl LoopbackTestTransport {
    fn new(base_url: &str, timeout: Duration) -> Result<Self> {
        Ok(Self {
            client: build_auth_http_client(timeout)?,
            base_url: validate_apps_e2e_loopback_url(base_url, APPS_E2E_CONTROL_PLANE_URL_ENV_VAR)?,
        })
    }
}

#[cfg(test)]
impl ControlPlaneTransport for LoopbackTestTransport {
    fn execute(&self, mut request: Request) -> reqwest::Result<Response> {
        assert!(
            is_trusted_control_plane_url(request.url()),
            "request must retain its approved production URL until transport execution: {}",
            request.url()
        );
        let query = request.url().query().map(str::to_string);
        let mut loopback_url = self.base_url.clone();
        loopback_url.set_path(request.url().path());
        loopback_url.set_query(query.as_deref());
        *request.url_mut() = loopback_url;
        self.client.execute(request)
    }
}

impl ControlPlaneClient {
    fn new(base_url: &str, client_version: &str, style: Style) -> Result<Self> {
        Self::new_with_timeout(
            base_url,
            client_version,
            style,
            CONTROL_PLANE_REQUEST_TIMEOUT,
        )
    }

    fn new_with_timeout(
        base_url: &str,
        client_version: &str,
        style: Style,
        request_timeout: Duration,
    ) -> Result<Self> {
        validate_control_plane_base_url(base_url)?;
        let client = build_control_plane_http_client(request_timeout)?;
        let control_plane = Self::build(base_url, client_version, style, client)?;
        #[cfg(test)]
        let control_plane = {
            let mut control_plane = control_plane;
            if let Some(loopback_url) = std::env::var_os(APPS_E2E_CONTROL_PLANE_URL_ENV_VAR) {
                let loopback_url = loopback_url.into_string().map_err(|_| {
                    anyhow::anyhow!("{APPS_E2E_CONTROL_PLANE_URL_ENV_VAR} must be UTF-8")
                })?;
                control_plane.test_transport = Some(Box::new(LoopbackTestTransport::new(
                    &loopback_url,
                    request_timeout,
                )?));
            }
            control_plane
        };
        Ok(control_plane)
    }

    fn build(base_url: &str, client_version: &str, style: Style, client: Client) -> Result<Self> {
        let client_version_text = client_version.to_string();
        let client_version = HeaderValue::from_str(client_version)
            .context("Apps Platform client version is not a valid HTTP header value")?;
        Ok(Self {
            client,
            #[cfg(test)]
            test_transport: None,
            base_url: base_url.to_string(),
            client_version,
            client_version_text,
            traceparent: std::env::var("TRACEPARENT")
                .ok()
                .as_deref()
                .and_then(inherited_traceparent),
            style,
        })
    }

    #[cfg(test)]
    fn new_for_test(
        base_url: &str,
        client_version: &str,
        style: Style,
        request_timeout: Duration,
        transport: Box<dyn ControlPlaneTransport>,
    ) -> Result<Self> {
        validate_control_plane_base_url(base_url)?;
        let mut client = Self::build(
            base_url,
            client_version,
            style,
            build_auth_http_client(request_timeout)?,
        )?;
        client.test_transport = Some(transport);
        Ok(client)
    }

    fn client_version_text(&self) -> &str {
        &self.client_version_text
    }

    fn contract(&self, credential: &ComposeSessionCredential) -> Result<Value> {
        let url = self.endpoint(APPS_CONTRACT_PATH)?;
        self.authorized_json_request(credential, "GET", APPS_CONTRACT_PATH, |authorization| {
            self.standard_request(self.client.get(url.clone()), authorization)
                .build()
                .context("build Apps Platform contract request")
        })
    }

    fn plan(
        &self,
        credential: &ComposeSessionCredential,
        request: &PlanRequest<'_>,
    ) -> Result<Value> {
        let url = self.endpoint(APPS_PLAN_PATH)?;
        self.authorized_json_request(credential, "POST", APPS_PLAN_PATH, |authorization| {
            self.standard_request(self.client.post(url.clone()), authorization)
                .json(request)
                .build()
                .context("build Apps Platform plan request")
        })
    }

    fn list_apps(
        &self,
        credential: &ComposeSessionCredential,
        scope: Option<&str>,
        include_deleted: bool,
    ) -> Result<Value> {
        let mut query = Vec::new();
        if let Some(scope) = scope {
            query.push(("scope", scope.to_string()));
        }
        if include_deleted {
            query.push(("include_deleted", "true".to_string()));
        }
        let url = self.apps_url(&query)?;
        self.get_url(credential, url)
    }

    fn get_app(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        environment: Option<&str>,
    ) -> Result<Value> {
        let query = environment
            .map(|environment| vec![("environment", environment.to_string())])
            .unwrap_or_default();
        let url = self.app_url(app_id, &query)?;
        self.get_url(credential, url)
    }

    fn versions(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        environment: Option<&str>,
    ) -> Result<Value> {
        let query = environment
            .map(|environment| vec![("environment", environment.to_string())])
            .unwrap_or_default();
        self.get_app_resource(credential, app_id, "versions", &query)
    }

    fn initialize(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        request: &Value,
    ) -> Result<Value> {
        let url = self.app_action_url(app_id, "initialize")?;
        let path = url.path().to_string();
        self.authorized_json_request(credential, "POST", &path, |authorization| {
            self.standard_request(self.client.post(url.clone()), authorization)
                .json(request)
                .build()
                .context("build Apps Platform initialize request")
        })
    }

    fn reserve(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        request: &Value,
    ) -> Result<Value> {
        let url = self.app_action_url(app_id, "reserve")?;
        let path = url.path().to_string();
        self.authorized_json_request(credential, "POST", &path, |authorization| {
            self.standard_request(self.client.post(url.clone()), authorization)
                .json(request)
                .build()
                .context("build Apps Platform reserve request")
        })
    }

    fn deploy(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        artifact: &Path,
        options: &DeployOptions,
    ) -> Result<Value> {
        let url = self.app_action_url(app_id, "deploy")?;
        let path = url.path().to_string();
        self.authorized_json_request(credential, "POST", &path, |authorization| {
            let form = deploy_form(artifact, options)?;
            self.standard_request(self.client.post(url.clone()), authorization)
                .multipart(form)
                .build()
                .context("build Apps Platform deploy request")
        })
    }

    fn rollback(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        request: &RollbackRequest<'_>,
    ) -> Result<Value> {
        let url = self.app_action_url(app_id, "rollback")?;
        let path = url.path().to_string();
        self.authorized_json_request(credential, "POST", &path, |authorization| {
            self.standard_request(self.client.post(url.clone()), authorization)
                .json(request)
                .build()
                .context("build Apps Platform rollback request")
        })
    }

    fn delete_app(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        request: &DeleteAppRequest<'_>,
    ) -> Result<Value> {
        let url = self.app_url(app_id, &[])?;
        let path = url.path().to_string();
        let authorization = credential.authorization_header();
        let http_request = self
            .standard_request(self.client.delete(url), authorization)
            .json(request)
            .build()
            .context("build Apps Platform delete request")?;
        self.style.verbose(&format!("DELETE {path}"));
        let response = self
            .execute_request(http_request)
            .map_err(|_| delete_outcome_unknown())?;
        let status = response.status();
        let trace_id = response_header_trace_id(&response)
            .filter(|trace_id| credential.redact(trace_id) == *trace_id);
        let body = read_limited_response_body(
            response,
            CONTROL_PLANE_RESPONSE_MAX_BYTES,
            "Apps Platform control-plane",
        )
        .map_err(|_| with_failure_trace_id(delete_outcome_unknown(), trace_id.as_deref()))?;
        let trace_id = trace_id.or_else(|| {
            response_body_trace_id(&body)
                .filter(|trace_id| credential.redact(trace_id) == *trace_id)
        });
        self.style
            .verbose(&format!("DELETE {path} -> {status} ({} bytes)", body.len()));
        if !status.is_success() {
            return Err(with_failure_trace_id(
                control_plane_http_failure("DELETE", &path, status, &body, credential),
                trace_id.as_deref(),
            ));
        }
        let mut value: Value = serde_json::from_str(&body)
            .map_err(|_| with_failure_trace_id(delete_outcome_unknown(), trace_id.as_deref()))?;
        if !value.is_object() {
            return Err(with_failure_trace_id(
                delete_outcome_unknown(),
                trace_id.as_deref(),
            ));
        }
        redact_json_value(&mut value, credential)
            .map_err(|_| with_failure_trace_id(delete_outcome_unknown(), trace_id.as_deref()))?;
        retain_response_trace_id(&mut value, trace_id.as_deref());
        Ok(value)
    }

    fn ready(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        version_id: &str,
        environment: Option<&str>,
    ) -> Result<Value> {
        let mut query = Vec::new();
        if let Some(environment) = environment {
            query.push(("environment", environment.to_string()));
        }
        query.push(("version_id", version_id.to_string()));
        self.get_app_resource(credential, app_id, "ready", &query)
    }

    fn debug(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        environment: Option<&str>,
        version_id: Option<&str>,
        tail_lines: Option<u16>,
    ) -> Result<Value> {
        let mut query = Vec::new();
        if let Some(environment) = environment {
            query.push(("environment", environment.to_string()));
        }
        if let Some(version_id) = version_id {
            query.push(("version_id", version_id.to_string()));
        }
        if let Some(tail_lines) = tail_lines {
            query.push(("tail_lines", tail_lines.to_string()));
        }
        self.get_app_resource(credential, app_id, "debug", &query)
    }

    fn get_access(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        environment: Option<&str>,
    ) -> Result<Value> {
        let query = environment
            .map(|environment| vec![("environment", environment.to_string())])
            .unwrap_or_default();
        self.get_app_resource(credential, app_id, "access", &query)
    }

    fn set_access(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        request: &AccessRequest<'_>,
    ) -> Result<Value> {
        let url = self.app_resource_url(app_id, "access", &[])?;
        let path = url.path().to_string();
        self.authorized_json_request(credential, "PUT", &path, |authorization| {
            self.standard_request(self.client.put(url.clone()), authorization)
                .json(request)
                .build()
                .context("build Apps Platform access update request")
        })
    }

    fn set_visibility(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        visibility: &str,
        environment: Option<&str>,
    ) -> Result<Value> {
        let url = self.app_resource_url(app_id, "visibility", &[])?;
        let path = url.path().to_string();
        let request = VisibilityRequest {
            visibility,
            environment,
        };
        self.authorized_json_request(credential, "PUT", &path, |authorization| {
            self.standard_request(self.client.put(url.clone()), authorization)
                .json(&request)
                .build()
                .context("build Apps Platform visibility update request")
        })
    }

    fn update_community_grant(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        community_id: &str,
        lifecycle_id: &str,
        action: &str,
        expected_revision: u64,
    ) -> Result<Value> {
        let url = self.community_grant_url(app_id, community_id)?;
        let path = request_path(&url);
        let method = match action {
            "grant" => "POST",
            "revoke" => "DELETE",
            _ => anyhow::bail!("unsupported community sharing action"),
        };
        let body = json!({
            "lifecycle_id": lifecycle_id,
            "expected_revision": expected_revision,
        });
        self.authorized_json_request(credential, method, &path, |authorization| {
            let request = if method == "POST" {
                self.client.post(url.clone())
            } else {
                self.client.delete(url.clone())
            };
            self.standard_request(request, authorization)
                .json(&body)
                .build()
                .context("build Apps Platform community sharing request")
        })
    }

    fn get_community_grant_revision(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        community_id: &str,
    ) -> Result<Value> {
        self.get_url(credential, self.community_grant_url(app_id, community_id)?)
    }

    fn community_grant_url(&self, app_id: &str, community_id: &str) -> Result<url::Url> {
        let mut url = self.app_url(app_id, &[])?;
        url.path_segments_mut()
            .map_err(|_| {
                anyhow::anyhow!("Apps Platform control-plane URL cannot contain path segments")
            })?
            .extend(["sharing", "communities", community_id]);
        Ok(url)
    }

    fn get_app_resource(
        &self,
        credential: &ComposeSessionCredential,
        app_id: &str,
        resource: &str,
        query: &[(&str, String)],
    ) -> Result<Value> {
        let url = self.app_resource_url(app_id, resource, query)?;
        self.get_url(credential, url)
    }

    fn get_url(&self, credential: &ComposeSessionCredential, url: url::Url) -> Result<Value> {
        let path = request_path(&url);
        self.authorized_json_request(credential, "GET", &path, |authorization| {
            self.standard_request(self.client.get(url.clone()), authorization)
                .build()
                .with_context(|| format!("build Apps Platform GET {path} request"))
        })
    }

    fn endpoint(&self, path: &str) -> Result<url::Url> {
        auth_url(&self.base_url, path)
            .with_context(|| format!("build Apps Platform control-plane {path} URL"))
    }

    fn app_action_url(&self, app_id: &str, action: &str) -> Result<url::Url> {
        self.app_resource_url(app_id, action, &[])
    }

    fn apps_url(&self, query: &[(&str, String)]) -> Result<url::Url> {
        let mut url = self.endpoint("/v1/agent/apps")?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (name, value) in query {
                pairs.append_pair(name, value);
            }
        }
        Ok(url)
    }

    fn app_url(&self, app_id: &str, query: &[(&str, String)]) -> Result<url::Url> {
        let mut url = self.apps_url(query)?;
        url.path_segments_mut()
            .map_err(|_| {
                anyhow::anyhow!("Apps Platform control-plane URL cannot contain path segments")
            })?
            .push(app_id);
        Ok(url)
    }

    fn app_resource_url(
        &self,
        app_id: &str,
        resource: &str,
        query: &[(&str, String)],
    ) -> Result<url::Url> {
        let mut url = self.app_url(app_id, query)?;
        url.path_segments_mut()
            .map_err(|_| {
                anyhow::anyhow!("Apps Platform control-plane URL cannot contain path segments")
            })?
            .push(resource);
        Ok(url)
    }

    fn standard_request(
        &self,
        request: RequestBuilder,
        authorization: Option<HeaderValue>,
    ) -> RequestBuilder {
        let request = request
            .header(USER_AGENT, apps_user_agent())
            .header(ACCEPT, "application/json")
            .header(
                HOTPOD_AGENT_CLIENT_VERSION_HEADER,
                self.client_version.clone(),
            );
        let request = match authorization {
            Some(authorization) => request.header(AUTHORIZATION, authorization),
            None => request,
        };
        match &self.traceparent {
            Some(traceparent) => request.header("traceparent", traceparent.clone()),
            None => request,
        }
    }

    fn authorized_json_request<F>(
        &self,
        credential: &ComposeSessionCredential,
        method: &str,
        path: &str,
        send: F,
    ) -> Result<Value>
    where
        F: Fn(Option<HeaderValue>) -> Result<Request>,
    {
        let authorization = credential.authorization_header();
        let (status, body, trace_id) =
            self.request_response(credential, method, path, &send, authorization)?;
        if !status.is_success() {
            return Err(with_failure_trace_id(
                control_plane_http_failure(method, path, status, &body, credential),
                trace_id.as_deref(),
            ));
        }
        let mut value: Value = serde_json::from_str(&body)
            .with_context(|| format!("parse Apps Platform {method} {path} response"))
            .map_err(|error| with_failure_trace_id(error, trace_id.as_deref()))?;
        if !value.is_object() {
            return Err(with_failure_trace_id(
                anyhow::anyhow!("Apps Platform {method} {path} response was not a JSON object"),
                trace_id.as_deref(),
            ));
        }
        redact_json_value(&mut value, credential)
            .with_context(|| format!("sanitize Apps Platform {method} {path} response"))
            .map_err(|error| with_failure_trace_id(error, trace_id.as_deref()))?;
        retain_response_trace_id(&mut value, trace_id.as_deref());
        Ok(value)
    }

    fn request_response<F>(
        &self,
        credential: &ComposeSessionCredential,
        method: &str,
        path: &str,
        send: &F,
        authorization: Option<HeaderValue>,
    ) -> Result<(StatusCode, String, Option<String>)>
    where
        F: Fn(Option<HeaderValue>) -> Result<Request>,
    {
        self.style.verbose(&format!("{method} {path}"));
        let request = send(authorization)?;
        let response = self
            .execute_request(request)
            .map_err(|error| network_failure(method, path, error))?;
        let status = response.status();
        // Capture correlation before the bounded reader consumes the response.
        let trace_id = response_header_trace_id(&response)
            .filter(|trace_id| credential.redact(trace_id) == *trace_id);
        let body = read_limited_response_body(
            response,
            CONTROL_PLANE_RESPONSE_MAX_BYTES,
            "Apps Platform control-plane",
        )
        .map_err(|error| with_failure_trace_id(error, trace_id.as_deref()))?;
        let trace_id = trace_id.or_else(|| {
            response_body_trace_id(&body)
                .filter(|trace_id| credential.redact(trace_id) == *trace_id)
        });
        self.style.verbose(&format!(
            "{method} {path} -> {status} ({} bytes)",
            body.len()
        ));
        Ok((status, body, trace_id))
    }

    fn execute_request(&self, request: Request) -> reqwest::Result<Response> {
        #[cfg(test)]
        if let Some(transport) = self.test_transport.as_ref() {
            return transport.execute(request);
        }
        self.client.execute(request)
    }
}

fn request_path(url: &url::Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

// Forward context without creating a CLI span or changing the caller's sampling
// decision. Future versions retain the known W3C prefix and opaque suffix.
fn inherited_traceparent(value: &str) -> Option<HeaderValue> {
    let bytes = value.as_bytes();
    if !(55..=512).contains(&bytes.len())
        || !bytes.iter().all(|byte| (b'!'..=b'~').contains(byte))
        || bytes[2] != b'-'
        || bytes[35] != b'-'
        || bytes[52] != b'-'
        || !lowercase_hex(&bytes[..2])
        || &bytes[..2] == b"ff"
        || !lowercase_hex(&bytes[3..35])
        || bytes[3..35].iter().all(|byte| *byte == b'0')
        || !lowercase_hex(&bytes[36..52])
        || bytes[36..52].iter().all(|byte| *byte == b'0')
        || !lowercase_hex(&bytes[53..55])
        || (bytes.len() > 55 && (&bytes[..2] == b"00" || bytes[55] != b'-'))
    {
        return None;
    }
    HeaderValue::from_str(value).ok()
}

fn lowercase_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn canonical_trace_id(value: &str) -> Option<String> {
    (value.len() == 32
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0'))
    .then(|| value.to_ascii_lowercase())
}

fn response_header_trace_id(response: &Response) -> Option<String> {
    response
        .headers()
        .get(HOTPOD_TRACE_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(canonical_trace_id)
}

fn response_value_trace_id(value: &Value) -> Option<String> {
    [value.get("trace_id"), value.pointer("/error/trace_id")]
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .find_map(canonical_trace_id)
}

fn response_body_trace_id(body: &str) -> Option<String> {
    response_value_trace_id(&serde_json::from_str::<Value>(body).ok()?)
}

fn retain_response_trace_id(value: &mut Value, trace_id: Option<&str>) {
    if let (Some(object), Some(trace_id)) = (value.as_object_mut(), trace_id) {
        object.insert("trace_id".to_string(), json!(trace_id));
    }
}

fn correlate_response_error(error: anyhow::Error, response: &Value) -> anyhow::Error {
    with_failure_trace_id(error, response_value_trace_id(response).as_deref())
}

fn build_control_plane_http_client(timeout: Duration) -> Result<Client> {
    Client::builder()
        .redirect(Policy::none())
        .timeout(timeout)
        .build()
        .context("build Apps Platform control-plane HTTP client")
}

fn redact_json_value(value: &mut Value, credential: &ComposeSessionCredential) -> Result<()> {
    match value {
        Value::String(text) => *text = credential.redact(text),
        Value::Array(items) => {
            for item in items {
                redact_json_value(item, credential)?;
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                if credential.redact(key) != *key {
                    anyhow::bail!(
                        "Apps Platform response contained the session credential in an object key"
                    );
                }
                redact_json_value(value, credential)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

#[cfg(test)]
fn validate_apps_e2e_loopback_url(value: &str, name: &str) -> Result<url::Url> {
    let url = url::Url::parse(value).with_context(|| format!("parse {name}"))?;
    let loopback_ip = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(_)) | None => false,
    };
    if url.scheme() != "http"
        || !loopback_ip
        || url.port().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!(
            "{name} must be an HTTP loopback IP origin with an explicit port and no userinfo, path, query, or fragment"
        );
    }
    Ok(url)
}

fn deploy_form(artifact: &Path, options: &DeployOptions) -> Result<multipart::Form> {
    let artifact_part = multipart::Part::file(artifact)
        .with_context(|| format!("open Apps Platform artifact {}", artifact.display()))?
        .file_name("artifact.tar.gz")
        .mime_str("application/gzip")
        .context("set Apps Platform artifact content type")?;
    let mut form = multipart::Form::new().part("artifact", artifact_part);
    for (name, value) in [
        ("environment", options.environment.as_deref()),
        ("version_id", options.version_id.as_deref()),
        ("deployment_id", options.deployment_id.as_deref()),
    ] {
        if let Some(value) = value {
            form = form.text(name.to_string(), value.to_string());
        }
    }
    Ok(form)
}

fn is_trusted_control_plane_url(url: &url::Url) -> bool {
    if is_blox_control_plane_url(url) {
        return true;
    }
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    let Some(url::Host::Domain(host)) = url.host() else {
        return false;
    };
    TRUSTED_CONTROL_PLANE_HOSTS
        .iter()
        .any(|trusted| host.eq_ignore_ascii_case(trusted))
}

fn on_blox() -> bool {
    std::env::var("IS_BLOX").as_deref() == Ok("true")
        && std::env::var("BLOX_WORKSTATION_ID").is_ok_and(|id| !id.is_empty())
}

// On Blox the operator sets BL_APPS_CONTROL_PLANE_URL and Roxy authenticates
// requests to that origin, so the CLI trusts it and sends no credentials.
fn is_blox_control_plane_url(url: &url::Url) -> bool {
    on_blox()
        && url.username().is_empty()
        && url.password().is_none()
        && std::env::var(APPS_BASE_URL_ENV_VAR)
            .ok()
            .and_then(|configured| url::Url::parse(&configured).ok())
            .is_some_and(|configured| configured.origin() == url.origin())
}

fn proxy_auth_for_url(base_url: &str) -> bool {
    url::Url::parse(base_url).is_ok_and(|url| is_blox_control_plane_url(&url))
}

fn uses_proxy_auth(matches: &ArgMatches) -> bool {
    matches
        .try_get_one::<String>("apps-base-url")
        .ok()
        .flatten()
        .is_some_and(|base_url| proxy_auth_for_url(base_url))
        || matches
            .subcommand()
            .is_some_and(|(_, child)| uses_proxy_auth(child))
}

fn validate_control_plane_base_url(base_url: &str) -> Result<()> {
    let contract_url = auth_url(base_url, APPS_CONTRACT_PATH)
        .context("build Apps Platform control-plane contract URL")?;
    if !is_trusted_control_plane_url(&contract_url) {
        anyhow::bail!(
            "Apps Platform control-plane URL must target an approved BuilderLab ingress over HTTPS, or the Blox-configured {APPS_BASE_URL_ENV_VAR} endpoint"
        );
    }
    Ok(())
}

fn read_limited_response_body(
    response: reqwest::blocking::Response,
    max_bytes: usize,
    description: &str,
) -> Result<String> {
    let mut bytes = Vec::new();
    response
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {description} response"))?;
    if bytes.len() > max_bytes {
        anyhow::bail!("{description} response exceeded {max_bytes} bytes");
    }
    String::from_utf8(bytes).with_context(|| format!("decode {description} response as UTF-8"))
}

fn apps_user_agent() -> String {
    format!("bl-apps/{}", env!("CARGO_PKG_VERSION"))
}

fn auth_required_error() -> anyhow::Error {
    failure(
        exit_codes::AUTH_REQUIRED,
        "auth_required",
        "BuilderLab CLI auth is required; run `bl auth login`",
    )
}

fn network_failure(method: &str, path: &str, error: reqwest::Error) -> anyhow::Error {
    failure(
        exit_codes::NETWORK,
        "network_error",
        format!("{method} {path} failed before receiving a response: {error}"),
    )
}

fn delete_outcome_unknown() -> anyhow::Error {
    failure(
        exit_codes::NETWORK,
        "delete_outcome_unknown",
        "The delete may have succeeded, but no complete JSON success response was received.\n\
         next_action: Before retrying, verify the same APP_ID and ENVIRONMENT with \
         `bl apps get <APP_ID> --environment <ENVIRONMENT>`; a successful delete reports \
         `app.status` as `deleted`.",
    )
}

// Error recovery fields are terminal-safe text. Successful JSON responses only
// redact the credential, preserving log newlines, tabs and arbitrary metadata.
fn sanitize_recovery_field(value: &Value, credential: &ComposeSessionCredential) -> Option<Value> {
    fn sanitize(value: &mut Value, credential: &ComposeSessionCredential) -> Result<()> {
        match value {
            Value::String(text) => *text = terminal_safe_text(&credential.redact(text)),
            Value::Array(items) => {
                for item in items {
                    sanitize(item, credential)?;
                }
            }
            Value::Object(object) => {
                for (key, value) in object {
                    if credential.redact(key) != *key || terminal_safe_text(key) != *key {
                        anyhow::bail!(
                            "Apps Platform recovery field contained an unsafe object key"
                        );
                    }
                    sanitize(value, credential)?;
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        Ok(())
    }
    let mut value = value.clone();
    sanitize(&mut value, credential).ok()?;
    Some(value)
}

fn app_id_from_path(path: &str) -> Option<&str> {
    let path = path.split('?').next().unwrap_or(path);
    path.strip_prefix("/v1/agent/apps/")
        .and_then(|rest| rest.split('/').next())
        .filter(|app_id| !app_id.is_empty() && *app_id != "plan")
}

fn is_app_scoped_path(path: &str) -> bool {
    app_id_from_path(path).is_some()
}

/// What a stable Compose error code means for the person running `bl`, and
/// the next step when the server sends none. The server's `error.message` is
/// never printed because it can reflect request values, so these are
/// CLI-owned, like the manifest validation diagnostics.
fn known_failure_explanation(
    method: &str,
    code: &str,
    app_id: Option<&str>,
) -> Option<(&'static str, Option<String>)> {
    let app = app_id.unwrap_or("<APP_ID>");
    Some(match code {
        // On the grant read, this conflict means the app has no sharing
        // lifecycle yet; `with_missing_lifecycle_step` explains that case.
        "community_grant_conflict" if method != "GET" => (
            "This app's community sharing changed at the same time, so nothing was changed.",
            Some(format!("Run `bl apps get {app}` to see who can open it now, then retry if it still needs changing.")),
        ),
        "community_grant_denied" => (
            "Only the app's owner, signed in to the app's workspace, can change its community sharing. Nothing was changed.",
            Some("If you own the app, run `bl workspace switch` to choose its workspace, then retry. To share with a community you also need to be a current member; `bl apps community list` shows yours.".to_string()),
        ),
        "tier_resolution_unavailable" => (
            "Apps Platform couldn't check your site allowance, so nothing was changed.",
            Some("Wait a minute, then run the same command again.".to_string()),
        ),
        "owner_site_quota_unavailable" => (
            "Apps Platform isn't accepting new deployments right now, so nothing was changed.",
            Some("Wait a minute, then run the same command again.".to_string()),
        ),
        "workspace_mismatch" => (
            "This app belongs to a different workspace than the one you're signed in to. Nothing was changed.",
            Some("Run `bl workspace switch` to choose the app's workspace, then try again.".to_string()),
        ),
        "workspace_binding_required" => (
            "Your session isn't tied to a workspace yet. Nothing was changed.",
            Some("Run `bl workspace switch` to choose a workspace, then try again.".to_string()),
        ),
        "owner_required" => (
            "Only the app's owner can do this. Nothing was changed.",
            Some("Ask the app's owner to make the change.".to_string()),
        ),
        "access_policy_update_in_progress" => (
            "Another change to who can open this app is still being applied.",
            Some("Wait a few seconds, then try again.".to_string()),
        ),
        "access_policy_conflict" => (
            "Who can open this app changed while this request was running.",
            Some(format!("Run `bl apps get {app}` to see who can open it now, then try again if it still needs changing.")),
        ),
        "app_not_found" => (
            "There's no app with that ID that you can manage here.",
            Some("Check the app ID with `bl apps list`.".to_string()),
        ),
        _ => return None,
    })
}

fn control_plane_http_failure(
    method: &str,
    path: &str,
    status: StatusCode,
    body: &str,
    credential: &ComposeSessionCredential,
) -> anyhow::Error {
    // The ingress intentionally returns an empty denial. Enrich only that
    // response using the already verified session; preserve explicit API errors
    // (including workspace/publisher denials) and never retry a mutation.
    let access_recovery = (status == StatusCode::FORBIDDEN && body.trim().is_empty())
        .then(|| credential.access_recovery())
        .flatten();
    let parsed = serde_json::from_str::<Value>(body).ok();
    let code = parsed
        .as_ref()
        .and_then(|value| value.pointer("/error/code"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            access_recovery.map_or("control_plane_request_failed", |recovery| recovery.code)
        });
    let validation = manifest_validation_diagnostic(status, code, parsed.as_ref());
    let known = known_failure_explanation(method, code, app_id_from_path(path));
    let code = terminal_safe_text(&credential.redact(code));
    let mut details = json!({"http_status": status.as_u16()});
    if !matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        if let Some(Value::Object(server_details)) = parsed
            .as_ref()
            .and_then(|value| value.pointer("/error/details"))
            .and_then(|value| sanitize_recovery_field(value, credential))
        {
            for (key, value) in server_details {
                // These fields describe the actual response and locally reviewed
                // manifest diagnostics; a server field cannot replace them.
                if key != "http_status" && key != "validation" {
                    details[&key] = value;
                }
            }
        }
    }
    let next_action = if status == StatusCode::UNAUTHORIZED {
        Some(json!(
            "Run `bl auth logout`, then `bl auth login` to replace your session."
        ))
    } else if let Some(recovery) = access_recovery {
        Some(json!(terminal_safe_text(
            &credential.redact(&recovery.next_action)
        )))
    } else {
        parsed
            .as_ref()
            .and_then(|value| {
                value
                    .get("next_action")
                    .or_else(|| value.pointer("/error/next_action"))
            })
            .and_then(|value| sanitize_recovery_field(value, credential))
            .or_else(|| {
                known
                    .as_ref()
                    .and_then(|(_, next_action)| next_action.as_deref())
                    .map(|next_action| json!(terminal_safe_text(&credential.redact(next_action))))
            })
            .or_else(|| {
                (status == StatusCode::FORBIDDEN).then(|| {
                    // Only a request about one app has an owner to ask.
                    json!(if is_app_scoped_path(path) {
                        "Check Apps access for this account and environment, and your workspace and app permissions. Ask the app owner to confirm your viewing or publishing access."
                    } else {
                        "Check Apps access for this account and environment, and your workspace permissions."
                    })
                })
            })
    };
    let mut message = format!("{method} {path} failed with {status} ({code})");
    if let Some((explanation, _)) = known.as_ref() {
        message.push('\n');
        message.push_str(explanation);
    }
    if let Some((diagnostic, guidance)) = validation {
        message.push_str("\nvalidation: ");
        message.push_str(diagnostic);
        message.push_str("\nrepair: ");
        message.push_str(guidance);
        details["validation"] = json!({"message": diagnostic, "next_action": guidance});
    }
    if let Some(action) = next_action.as_ref() {
        message.push_str("\nnext_action: ");
        if let Some(text) = action.as_str() {
            message.push_str(text);
        } else {
            message.push_str(&action.to_string());
        }
    }
    let exit_code = match status.as_u16() {
        401 => exit_codes::AUTH_REQUIRED,
        403 => exit_codes::FORBIDDEN,
        value if value >= 500 => exit_codes::NETWORK,
        _ => exit_codes::GENERAL,
    };
    let mut error = CliFailure::new(exit_code, &code, message);
    error.details = Some(details);
    error.next_action = next_action;
    anyhow::Error::new(error)
}

fn manifest_validation_diagnostic(
    status: StatusCode,
    code: &str,
    parsed: Option<&Value>,
) -> Option<(&'static str, &'static str)> {
    if status != StatusCode::BAD_REQUEST || code != "artifact_manifest_invalid" {
        return None;
    }
    // This code also covers decoder/reader errors and reflected manifest values.
    // Recognize only fixed public validator messages, returning CLI-owned text.
    // Never expose arbitrary error.message, even under a known validation code.
    Some(match parsed.and_then(|value| value.pointer("/error/message")).and_then(Value::as_str) {
        Some("artifact is missing hotpod.manifest.json") => (
            "artifact is missing hotpod.manifest.json",
            "Add hotpod.manifest.json at the archive root. Use the schema endpoint advertised by the selected control plane's `bl apps contract --json` runtime_info.contracts_path, then rebuild the artifact before deploying again.",
        ),
        Some("fetch-js manifest is missing required binding ASSETS") => (
            "fetch-js manifest is missing required binding ASSETS",
            "Add the ASSETS binding to hotpod.manifest.json. Check all required_bindings in the selected control plane's `bl apps contract --json` runtime_info, then rebuild the artifact before deploying again.",
        ),
        Some("fetch-js manifest is missing required binding HOTPOD") => (
            "fetch-js manifest is missing required binding HOTPOD",
            "Add the HOTPOD binding to hotpod.manifest.json. Check all required_bindings in the selected control plane's `bl apps contract --json` runtime_info, then rebuild the artifact before deploying again.",
        ),
        _ => (
            "artifact manifest was rejected",
            "Check hotpod.manifest.json against the schema endpoint and runtime requirements advertised by the selected control plane's `bl apps contract --json` runtime_info (contracts_path and required_bindings), then rebuild the artifact before deploying again.",
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::process::Command as ProcessCommand;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use sha2::{Digest, Sha256};
    use tiny_http::{Header, Response, Server};

    use super::*;

    const APPROVED_TEST_BASE_URL: &str = "https://compose-ctrl.test.blockstaging.build";
    const PROCESS_STDOUT_BEGIN: &str = "BL_APPS_E2E_STDOUT_BEGIN";
    const PROCESS_STDOUT_END: &str = "BL_APPS_E2E_STDOUT_END";

    #[derive(Clone)]
    struct ProcessResponse {
        status: u16,
        body: String,
        trace_id: Option<String>,
    }

    impl ProcessResponse {
        fn json(body: Value) -> Self {
            Self {
                status: 200,
                body: body.to_string(),
                trace_id: None,
            }
        }

        fn json_status(status: u16, body: Value) -> Self {
            Self {
                status,
                body: body.to_string(),
                trace_id: None,
            }
        }

        fn raw(status: u16, body: impl Into<String>) -> Self {
            Self {
                status,
                body: body.into(),
                trace_id: None,
            }
        }

        fn with_trace_id(mut self, trace_id: &str) -> Self {
            self.trace_id = Some(trace_id.to_string());
            self
        }
    }

    #[derive(Clone)]
    struct ProcessRequest {
        method: String,
        path: String,
        headers: BTreeMap<String, String>,
        body: Value,
        body_bytes: Vec<u8>,
    }

    struct ProcessServer {
        base_url: String,
        requests: Arc<Mutex<Vec<ProcessRequest>>>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl ProcessServer {
        fn start(responses: Vec<ProcessResponse>) -> Self {
            let server = Server::http("127.0.0.1:0").expect("bind Apps process test server");
            let base_url = format!("http://{}", server.server_addr());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let thread_requests = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                let mut responses = VecDeque::from(responses);
                while let Some(response) = responses.pop_front() {
                    let mut request = server
                        .recv_timeout(Duration::from_secs(10))
                        .expect("receive Apps process request")
                        .expect("Apps process request before timeout");
                    let headers = request
                        .headers()
                        .iter()
                        .map(|header| {
                            (
                                header.field.as_str().to_string().to_ascii_lowercase(),
                                header.value.as_str().to_string(),
                            )
                        })
                        .collect::<BTreeMap<_, _>>();
                    let mut body_bytes = Vec::new();
                    request
                        .as_reader()
                        .read_to_end(&mut body_bytes)
                        .expect("read Apps process request");
                    let body = if headers
                        .get("content-type")
                        .is_some_and(|value| value.starts_with("application/json"))
                    {
                        serde_json::from_slice(&body_bytes)
                            .expect("parse Apps process JSON request")
                    } else {
                        Value::Null
                    };
                    thread_requests
                        .lock()
                        .expect("lock Apps process requests")
                        .push(ProcessRequest {
                            method: request.method().as_str().to_string(),
                            path: request.url().to_string(),
                            headers,
                            body,
                            body_bytes,
                        });
                    let mut http_response = Response::from_string(response.body)
                        .with_status_code(response.status)
                        .with_header(
                            Header::from_bytes("Content-Type", "application/json")
                                .expect("build Apps process content type"),
                        );
                    if let Some(trace_id) = response.trace_id {
                        http_response.add_header(
                            Header::from_bytes(HOTPOD_TRACE_ID_HEADER, trace_id)
                                .expect("build Apps process trace header"),
                        );
                    }
                    request
                        .respond(http_response)
                        .expect("respond to Apps process request");
                }
            });
            Self {
                base_url,
                requests,
                handle: Some(handle),
            }
        }

        fn finish(mut self) -> Vec<ProcessRequest> {
            self.handle
                .take()
                .expect("Apps process server handle")
                .join()
                .expect("join Apps process server");
            self.requests
                .lock()
                .expect("lock Apps process requests")
                .clone()
        }
    }

    #[test]
    fn handoff_reports_verified_audience_and_exact_management_destination() {
        let portal = management_portal_url("https://app.builderlabstaging.xyz").unwrap();
        let inspected = json!({"app":{"app_id":"reading-list","workspace_id":"workspace-owner","host":"reading-list.apps.example"}});
        let access = json!({"ok":true,"app_id":"reading-list","visibility":"restricted","viewers":["viewer"],"effective_viewers":["owner","publisher","viewer"],"publishers":["publisher"],"shared_community_ids":["community"],"community_grant_revision":3});
        let result =
            build_app_handoff("reading-list", Some(&portal), &inspected, Ok(&access)).unwrap();
        assert_eq!(result["management_url"], "https://app.builderlabstaging.xyz/hosted-apps?app=reading-list&workspace=workspace-owner");
        assert_eq!(result["app_url"], "https://reading-list.apps.example/");
        assert_eq!(result["audience"]["status"], "verified");
        assert_eq!(result["audience"]["policy"], access);
        assert!(result["audience"]["reason"].is_null());
        assert_eq!(result["recipient_browser_access_verified"], false);
    }

    #[test]
    fn handoff_requires_complete_community_grant_reporting() {
        let portal = management_portal_url("https://app.builderlab.xyz").unwrap();
        let app = json!({"app":{"app_id":"demo","workspace_id":"team"}});
        for visibility in ["restricted", "organization"] {
            // No legacy workspace-grant fields are needed to confirm the audience.
            let complete = json!({"ok":true,"app_id":"demo","visibility":visibility,
                "viewers":[],"effective_viewers":["owner"],
                "community_grant_revision":0});
            let result = build_app_handoff("demo", Some(&portal), &app, Ok(&complete)).unwrap();
            assert_eq!(result["audience"]["status"], "verified");
            assert_eq!(result["audience"]["policy"], complete);

            for field in ["community_grant_revision"] {
                for invalid in [
                    None,
                    Some(Value::Null),
                    Some(json!("0")),
                    Some(json!(-1)),
                    Some(json!(0.5)),
                    Some(json!(false)),
                ] {
                    let mut policy = complete.clone();
                    if let Some(value) = invalid {
                        policy[field] = value;
                    } else {
                        policy.as_object_mut().unwrap().remove(field);
                    }
                    let result =
                        build_app_handoff("demo", Some(&portal), &app, Ok(&policy)).unwrap();
                    assert_eq!(result["audience"]["status"], "unknown", "{policy}");
                    assert!(result["audience"]["policy"].is_null());
                    assert_eq!(result["audience"]["reason"], "incomplete_policy");
                }
            }
            for field in [
                "shared_community_ids",
                "viewers",
                "effective_viewers",
                "publishers",
            ] {
                for value in [
                    Value::Null,
                    json!("team"),
                    json!({"id":"team"}),
                    json!(["team", 7]),
                ] {
                    let mut policy = complete.clone();
                    policy[field] = value;
                    let result =
                        build_app_handoff("demo", Some(&portal), &app, Ok(&policy)).unwrap();
                    assert_eq!(result["audience"]["status"], "unknown", "{policy}");
                    assert!(result["audience"]["policy"].is_null());
                }
            }
        }
    }

    #[test]
    fn handoff_never_infers_private_access_from_missing_or_wrong_app_policy() {
        let portal = management_portal_url("https://app.builderlab.xyz").unwrap();
        let app = json!({"app":{"app_id":"demo","workspace_id":"team","host":"evil.example/path"}});
        for policy in [
            None,
            Some(json!({"ok":true,"app_id":"other","visibility":"restricted"})),
            Some(json!({"ok":true,"app_id":"demo"})),
            Some(
                json!({"ok":true,"app_id":"demo","visibility":"restricted","viewers":[],"effective_viewers":["owner"]}),
            ),
        ] {
            let access = policy.context("policy unavailable");
            let result = build_app_handoff("demo", Some(&portal), &app, access.as_ref()).unwrap();
            assert_eq!(result["audience"]["status"], "unknown");
            assert!(result["audience"]["policy"].is_null());
            assert!(result["app_url"].is_null());
        }
        let unavailable = anyhow::anyhow!("policy unavailable");
        assert!(build_app_handoff("other", Some(&portal), &app, Err(&unavailable)).is_err());
    }

    #[test]
    fn handoff_next_action_matches_whether_a_link_and_audience_exist() {
        let portal = management_portal_url("https://app.builderlab.xyz").unwrap();
        let app = json!({"app":{"app_id":"demo","workspace_id":"team"}});
        let access = json!({"ok":true,"app_id":"demo","visibility":"organization","viewers":[],"community_grant_revision":1});
        let unavailable = anyhow::anyhow!("policy unavailable");
        for (portal, policy, starts, no_link) in [
            (Some(&portal), Ok(&access), "Report the current audience beside Open app and Share & manage.", false),
            (None, Ok(&access), "Report the current audience beside Open app. ", true),
            (Some(&portal), Err(&unavailable), "App access could not be confirmed. Report the audience as unknown and provide Share & manage;", false),
            (None, Err(&unavailable), "App access could not be confirmed. Report the audience as unknown; do not claim", true),
        ] {
            let handoff = build_app_handoff("demo", portal, &app, policy).unwrap();
            let next_action = handoff["next_action"].as_str().unwrap();
            assert!(next_action.starts_with(starts), "{next_action}");
            assert_eq!(next_action.contains("There is no Share & manage link"), no_link, "{next_action}");
            assert_eq!(next_action.contains("Open Hosted Apps in the BuilderLab portal"), no_link, "{next_action}");
        }
    }

    #[test]
    fn handoff_rejects_non_origin_management_urls() {
        for value in [
            "http://app.example",
            "https://user@app.example",
            "https://app.example/path",
            "https://app.example/?token=secret",
            "https://app.example/#fragment",
        ] {
            assert!(management_portal_url(value).is_err(), "{value}");
        }
    }

    #[test]
    fn handoff_reports_transport_failures_without_exposing_error_text() {
        let portal = management_portal_url("https://app.builderlab.xyz").unwrap();
        let app = json!({"app":{"app_id":"demo","workspace_id":"team"}});
        let error = failure(
            exit_codes::NETWORK,
            "network_error",
            "sensitive transport detail",
        )
        .context("policy read");
        let handoff = build_app_handoff("demo", Some(&portal), &app, Err(&error)).unwrap();
        assert_eq!(handoff["audience"]["status"], "unknown");
        assert_eq!(handoff["audience"]["reason"], "unavailable");
        assert!(!handoff.to_string().contains("sensitive transport detail"));
    }

    #[test]
    fn who_can_open_reads_the_same_however_compose_shapes_the_policy() {
        let names = BTreeMap::from([("buzz-alpha".to_string(), "Alpha Team".to_string())]);
        for (policy, caller_is_owner, expected) in [
            // Compose lists the owner among the viewers and drops effective_viewers.
            (
                json!({"visibility":"organization","owner":"me","viewers":["me"]}),
                true,
                "Everyone in the app's workspace.",
            ),
            // Workspace apps never count other people; everyone already can.
            (
                json!({"visibility":"organization","owner":"me","viewers":["me","a"],"shared_community_ids":["buzz-alpha"]}),
                true,
                "Everyone in the app's workspace. So can members of the Buzz community Alpha Team.",
            ),
            // A missing and a null community list both mean none.
            (
                json!({"visibility":"restricted","owner":"me","viewers":["me"],"effective_viewers":["me"]}),
                true,
                "Only you.",
            ),
            (
                json!({"visibility":"restricted","owner":"me","viewers":["me"],"effective_viewers":["me"],"shared_community_ids":null}),
                true,
                "Only you.",
            ),
            // Leftover viewers and publishers are counted, without the owner.
            (
                json!({"visibility":"restricted","owner":"me","viewers":["me","a"],"effective_viewers":["me","a","pub"],"shared_community_ids":["buzz-alpha","buzz-beta"]}),
                true,
                "Only you. 2 other people can also open it. So can members of 2 Buzz communities: Alpha Team, buzz-beta.",
            ),
            (
                json!({"visibility":"restricted","owner":"me","viewers":["a"],"publishers":["a"]}),
                false,
                "Only the app's owner. 1 other person can also open it.",
            ),
        ] {
            assert_eq!(
                who_can_open(&policy, None, caller_is_owner, &names),
                expected,
                "{policy}"
            );
        }
        // With no owner anywhere, the owner can't be left out, so don't count.
        let ownerless =
            json!({"visibility":"restricted","viewers":["me"],"effective_viewers":["me"]});
        assert_eq!(who_can_open(&ownerless, None, true, &names), "Only you.");
        // The app's owner from inspection fills in for a policy without one.
        let two =
            json!({"visibility":"restricted","viewers":["me","a"],"effective_viewers":["me","a"]});
        assert_eq!(
            who_can_open(&two, Some("me"), true, &names),
            "Only you. 1 other person can also open it."
        );
    }

    #[test]
    fn get_summary_says_who_can_open_the_app_beside_its_links() {
        let portal = management_portal_url("https://app.builderlabstaging.xyz").unwrap();
        let inspected = json!({"app":{"app_id":"hello","name":"Hello","role":"owner","workspace_id":"ws","host":"hello.apps.example","status":"running","active_version_id":"v1"}});
        let access = json!({"ok":true,"app_id":"hello","owner":"me","visibility":"organization","viewers":["me"],"shared_community_ids":["buzz-alpha"],"community_grant_revision":3});
        let names = BTreeMap::from([("buzz-alpha".to_string(), "Alpha Team".to_string())]);
        let handoff = build_app_handoff("hello", Some(&portal), &inspected, Ok(&access)).unwrap();
        assert_eq!(
            app_summary_text(&inspected, &handoff, &names),
            "Hello (hello)\n\
             Open app: https://hello.apps.example/\n\
             Who can open it: Everyone in the app's workspace. So can members of the Buzz community Alpha Team.\n\
             Share & manage: https://app.builderlabstaging.xyz/hosted-apps?app=hello&workspace=ws\n\
             Status: running, version v1\n"
        );
        // JSON keeps IDs; names are only looked up for people reading the text.
        assert_eq!(
            handoff["who_can_open"],
            "Everyone in the app's workspace. So can members of the Buzz community buzz-alpha."
        );

        let denied = control_plane_http_failure(
            "GET",
            "/v1/agent/apps/hello/access",
            StatusCode::FORBIDDEN,
            &json!({"error":{"code":"publisher_not_approved"}}).to_string(),
            &test_credential("credential-secret"),
        );
        let handoff = build_app_handoff("hello", None, &inspected, Err(&denied)).unwrap();
        let text = app_summary_text(&inspected, &handoff, &BTreeMap::new());
        assert!(
            text.contains(
                "Who can open it: Unknown, because this account can't read the app's access."
            ),
            "{text}"
        );
        assert!(text.contains("Share & manage: Open Hosted Apps in the BuilderLab portal and use Share & manage on hello."), "{text}");
        assert!(handoff["who_can_open"].is_null());

        let failed = failure(exit_codes::GENERAL, "invalid_json", "bad body").context("read");
        let handoff = build_app_handoff("hello", None, &inspected, Err(&failed)).unwrap();
        assert_eq!(handoff["audience"]["reason"], "request_failed");
        let text = app_summary_text(&inspected, &handoff, &BTreeMap::new());
        assert!(
            text.contains(
                "Who can open it: Unknown, because the request for the app's access failed."
            ),
            "{text}"
        );
    }

    #[test]
    fn get_summary_is_terminal_safe() {
        let inspected = json!({"app":{"app_id":"hello","name":"Evil\u{1b}[31m name","workspace_id":"ws","status":"idle"}});
        let access = json!({"ok":true,"app_id":"hello","visibility":"restricted","viewers":[],"effective_viewers":[],"shared_community_ids":["c"],"community_grant_revision":1});
        let names = BTreeMap::from([("c".to_string(), "bad\u{1b}]8;;x\u{7}".to_string())]);
        let handoff = build_app_handoff("hello", None, &inspected, Ok(&access)).unwrap();
        let text = app_summary_text(&inspected, &handoff, &names);
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(!text.contains('\u{7}'), "{text:?}");
    }

    #[test]
    fn community_change_text_reports_what_the_server_returned() {
        let names = BTreeMap::from([("buzz-alpha".to_string(), "Alpha Team".to_string())]);
        let granted = json!({"ok":true,"shared_community_ids":["buzz-alpha"]});
        let revoked = json!({"ok":true,"shared_community_ids":null});
        for (action, response, first_line) in [
            ("grant", &granted, "Members of the Buzz community Alpha Team can open demo now, whatever its visibility."),
            ("revoke", &revoked, "demo is no longer shared with the Buzz community Alpha Team."),
            ("grant", &revoked, "demo isn't shared with the Buzz community Alpha Team."),
            ("revoke", &granted, "demo is still shared with the Buzz community Alpha Team."),
        ] {
            let text = community_change_text("demo", "buzz-alpha", action, response, &names);
            assert_eq!(
                text,
                format!("{first_line}\nRun `bl apps get demo` to see everyone who can open it.\n")
            );
        }
    }

    #[test]
    fn joined_communities_accept_both_field_casings_and_explain_a_missing_link() {
        let communities = joined_communities(
            StatusCode::OK,
            &json!({"communities":[
                {"id":"c1","name":"One","normalized_host":"one.example"},
                {"id":"c2","name":"Two","normalizedHost":"two.example"},
                {"id":"c3"}
            ]})
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            joined_communities_text(&communities),
            "c1  One (one.example)\nc2  Two (two.example)\nc3\n\
             Share an app with one: bl apps community grant <APP_ID> <COMMUNITY_ID>\n"
        );
        assert_eq!(
            joined_communities_text(&[]),
            "You haven't joined any Buzz community yet.\n"
        );

        // Wire JSON leaves an empty list out, so an object without it is none.
        assert!(joined_communities(StatusCode::OK, "{}").unwrap().is_empty());

        let error = joined_communities(
            StatusCode::NOT_FOUND,
            &json!({"error":{"code":"missing_mapping","message":"private upstream detail"}})
                .to_string(),
        )
        .unwrap_err();
        let (_, payload) = failure_info(&error);
        assert_eq!(payload["error"]["code"], "missing_mapping");
        assert_eq!(
            payload["next_action"],
            "Connect your Buzz identity on the Buzz page of the BuilderLab portal, then retry."
        );
        assert!(!payload.to_string().contains("private upstream detail"));
        let error = joined_communities(StatusCode::UNAUTHORIZED, "").unwrap_err();
        assert_eq!(failure_info(&error).0, exit_codes::AUTH_REQUIRED);
    }

    #[test]
    fn joined_communities_never_print_server_text_or_read_a_stray_page_as_none() {
        for (status, body, code, exit_code, explanation) in [
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "<html>private upstream detail</html>".to_string(),
                "community_list_failed",
                exit_codes::NETWORK,
                "couldn't list your Buzz communities right now",
            ),
            (
                StatusCode::FORBIDDEN,
                json!({"error":{"code":"Not A Code \u{1b}","message":"private upstream detail"}})
                    .to_string(),
                "community_list_failed",
                exit_codes::FORBIDDEN,
                "This account can't list Buzz communities.",
            ),
            // A login or proxy page that answers 200 must not look like an empty account.
            (
                StatusCode::OK,
                "<html>private upstream detail</html>".to_string(),
                "community_list_invalid_response",
                exit_codes::GENERAL,
                "didn't return a usable list",
            ),
            (
                StatusCode::OK,
                json!({"communities":"private upstream detail"}).to_string(),
                "community_list_invalid_response",
                exit_codes::GENERAL,
                "didn't return a usable list",
            ),
            (
                StatusCode::OK,
                json!(["private upstream detail"]).to_string(),
                "community_list_invalid_response",
                exit_codes::GENERAL,
                "didn't return a usable list",
            ),
        ] {
            let error = joined_communities(status, &body).unwrap_err();
            let (exit, payload) = failure_info(&error);
            assert_eq!(exit, exit_code, "{body}");
            assert_eq!(payload["error"]["code"], code, "{body}");
            let message = payload["error"]["message"].as_str().unwrap();
            assert!(message.contains(explanation), "{message}");
            assert!(payload["next_action"].is_string(), "{payload}");
            assert!(
                !payload.to_string().contains("private upstream detail"),
                "{payload}"
            );
        }
    }

    #[test]
    fn sharing_help_uses_workspace_and_private_and_hides_individual_viewers() {
        let mut apps = command();
        assert!(apps.find_subcommand("handoff").unwrap().is_hide_set());
        let access = apps.find_subcommand("access").unwrap();
        assert!(access.find_subcommand("set").unwrap().is_hide_set());
        let help = |path: &[&str]| {
            let mut command = command();
            for name in path {
                command = command.find_subcommand(name).unwrap().clone();
            }
            command.render_long_help().to_string()
        };
        let mut all = String::new();
        for path in [
            &["get"][..],
            &["create"],
            &["access"],
            &["access", "get"],
            &["community"],
            &["community", "grant"],
            &["community", "revoke"],
            &["community", "list"],
            &["visibility"],
        ] {
            let text = help(path);
            all.push_str(&text);
            // Every positional argument says what to pass.
            let mut command = command();
            for name in path {
                command = command.find_subcommand(name).unwrap().clone();
            }
            for arg in command.get_positionals() {
                assert!(arg.get_help().is_some(), "{path:?} {}", arg.get_id());
            }
        }
        assert!(help(&["visibility"]).contains("`private` for only you"));
        assert!(help(&["community", "grant"]).contains("bl apps community list"));
        for gone in [
            "people you add",
            "--viewer",
            "auth0|",
            "bl apps handoff",
            "approved ingress",
        ] {
            assert!(!all.contains(gone), "{gone}");
        }
        assert!(!apps.render_long_help().to_string().contains("handoff"));
    }

    #[test]
    fn bl_apps_e2e_process_helper() {
        let Some(args) = std::env::var_os("BL_APPS_E2E_ARGS") else {
            return;
        };
        let args = serde_json::from_str::<Vec<String>>(
            args.to_str().expect("BL_APPS_E2E_ARGS must be UTF-8"),
        )
        .expect("parse BL_APPS_E2E_ARGS");
        let auth_url = std::env::var(APPS_E2E_AUTH_URL_ENV_VAR)
            .expect("Apps E2E helper requires an explicit auth URL");
        let auth_url = validate_apps_e2e_loopback_url(&auth_url, APPS_E2E_AUTH_URL_ENV_VAR)
            .expect("validate Apps E2E auth URL");
        let credential = std::env::var(APPS_E2E_CREDENTIAL_ENV_VAR)
            .expect("Apps E2E helper requires an explicit synthetic credential");
        assert!(
            credential.starts_with("apps-e2e-only."),
            "Apps E2E helper accepts only synthetic test credentials"
        );
        let temp = tempfile::tempdir().expect("create isolated Apps E2E home");
        let bl_home = temp.path().join("bl-home");
        let storage_path = temp.path().join("auth-sessions.json");
        fs::create_dir_all(&bl_home).expect("create isolated Apps E2E bl home");
        fs::write(bl_home.join("config.yaml"), "org: test\n")
            .expect("write isolated Apps E2E config");
        let service_url = format!("{}/api/goose", auth_url.as_str().trim_end_matches('/'));
        let mut hasher = Sha256::new();
        hasher.update(b"default");
        hasher.update([0]);
        hasher.update(service_url.as_bytes());
        let storage_key = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        fs::write(
            &storage_path,
            serde_json::to_vec_pretty(&json!({
                storage_key: {
                    "sessionCredential": credential,
                    "expiresAt": "2099-01-01T00:00:00Z"
                }
            }))
            .expect("serialize isolated Apps E2E storage"),
        )
        .expect("write isolated Apps E2E storage");
        std::env::set_var("BL_HOME", &bl_home);
        std::env::set_var("BL_AUTH_STORAGE", "file");
        std::env::set_var("BL_AUTH_STORAGE_FILE", &storage_path);
        std::env::set_var("KGOOSE_BASE_URL", auth_url.as_str());
        std::env::remove_var("BL_SKILLS_PROFILE");
        std::env::remove_var("KGOOSE_PLAYPEN");
        if std::env::var("BL_APPS_E2E_PROXY").as_deref() == Ok("true") {
            fs::remove_file(bl_home.join("config.yaml")).expect("remove local org");
            fs::remove_file(&storage_path).expect("remove local credentials");
            std::env::set_var("IS_BLOX", "true");
            std::env::set_var("BLOX_WORKSTATION_ID", "test-workstation");
        }
        println!("{PROCESS_STDOUT_BEGIN}");
        crate::finish_bl(crate::run_bl_with_argv(args));
        println!("{PROCESS_STDOUT_END}");
    }

    fn process_auth_response() -> ProcessResponse {
        ProcessResponse::json(json!({
            "subject": "auth0|apps-user",
            "email": "apps@example.com",
            "name": "Apps User",
            "expires_at": "2099-01-01T00:00:00Z",
            "workspaces": {"active": [{"name": "Test Workspace"}]}
        }))
    }

    fn process_command(
        auth_server: &ProcessServer,
        control_plane: &ProcessServer,
        args: &[&str],
        credential: &str,
    ) -> ProcessCommand {
        assert!(credential.starts_with("apps-e2e-only."));
        let argv = std::iter::once("bl")
            .chain(args.iter().copied())
            .map(str::to_string)
            .collect::<Vec<_>>();
        let mut command = ProcessCommand::new(std::env::current_exe().expect("current test exe"));
        command
            .args([
                "--exact",
                "bl::apps::tests::bl_apps_e2e_process_helper",
                "--nocapture",
            ])
            .env("BL_APPS_E2E_ARGS", serde_json::to_string(&argv).unwrap())
            .env(APPS_E2E_CONTROL_PLANE_URL_ENV_VAR, &control_plane.base_url)
            .env(APPS_E2E_AUTH_URL_ENV_VAR, &auth_server.base_url)
            .env(APPS_E2E_CREDENTIAL_ENV_VAR, credential)
            .env_remove("BL_HOME")
            .env_remove("BL_AUTH_STORAGE")
            .env_remove("BL_AUTH_STORAGE_FILE")
            .env_remove("KGOOSE_BASE_URL")
            .env_remove("BL_SKILLS_PROFILE")
            .env_remove("KGOOSE_PLAYPEN");
        command.env_remove("BL_APPS_E2E_PROXY");
        command.env_remove(APPS_BASE_URL_ENV_VAR);
        command.env_remove("BL_APPS_MANAGEMENT_BASE_URL");
        command.env_remove("TRACEPARENT");
        command
    }

    fn process_stdout(output: &std::process::Output) -> String {
        let stdout = String::from_utf8(output.stdout.clone()).expect("Apps process stdout UTF-8");
        let start = stdout
            .find(PROCESS_STDOUT_BEGIN)
            .expect("Apps process stdout begin marker")
            + PROCESS_STDOUT_BEGIN.len();
        let end = stdout[start..]
            .find(PROCESS_STDOUT_END)
            .map(|offset| start + offset)
            .expect("Apps process stdout end marker");
        stdout[start..end].trim().to_string()
    }

    fn assert_process_auth(request: &ProcessRequest, credential: &str) {
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/goose/v1/auth/me");
        assert_eq!(
            request
                .headers
                .get("x-bb-session-credential")
                .map(String::as_str),
            Some(credential)
        );
    }

    fn assert_process_control_plane(
        request: &ProcessRequest,
        method: &str,
        path: &str,
        credential: &str,
    ) {
        assert_eq!(request.method, method);
        assert_eq!(request.path, path);
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some(format!("BBIdentity {credential}").as_str())
        );
        assert_eq!(
            request
                .headers
                .get("x-hotpod-agent-client-version")
                .map(String::as_str),
            Some("0.2.0")
        );
        for forbidden in [
            "cookie",
            "x-bb-session-credential",
            "x-forwarded-user",
            "x-forwarded-workspace-id",
        ] {
            assert!(!request.headers.contains_key(forbidden));
        }
    }

    #[test]
    fn apps_e2e_destinations_require_explicit_http_loopback_ip_origins() {
        for valid in ["http://127.0.0.1:1234", "http://[::1]:4321"] {
            assert!(validate_apps_e2e_loopback_url(valid, "test URL").is_ok());
        }
        for invalid in [
            "http://192.0.2.1:1234",
            "https://127.0.0.1:1234",
            "http://localhost:1234",
            "http://user@127.0.0.1:1234",
            "http://127.0.0.1:1234/path",
            "http://127.0.0.1:1234/?query=yes",
            "http://127.0.0.1:1234/#fragment",
            "http://127.0.0.1",
        ] {
            let error = validate_apps_e2e_loopback_url(invalid, "test URL")
                .expect_err("reject unsafe Apps E2E destination");
            assert!(error.to_string().contains("HTTP loopback IP origin"));
        }
    }

    #[test]
    fn bl_apps_contract_process_covers_auth_dispatch_output_and_redaction() {
        let credential = "apps-e2e-only.contract.session+credential";
        let contract = json!({
            "ok": true,
            "contract_version": "2026-06-30",
            "reflected": credential,
            "nested": {"message": format!("prefix {credential}\u{1b}[31m\u{202e} suffix")}
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(contract)]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "contract",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps contract process command");
        assert!(
            output.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = process_stdout(&output);
        assert!(!stdout.contains(credential));
        let value = serde_json::from_str::<Value>(&stdout).expect("parse contract process output");
        assert_eq!(value["contract_version"], "2026-06-30");
        assert_eq!(value["reflected"], "[REDACTED]");
        assert_eq!(
            value["nested"]["message"],
            "prefix [REDACTED]\u{1b}[31m\u{202e} suffix"
        );
        let auth_requests = auth_server.finish();
        let control_requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_process_control_plane(&control_requests[0], "GET", APPS_CONTRACT_PATH, credential);
    }

    #[test]
    fn bl_apps_list_process_sends_filters_and_preserves_inventory() {
        let credential = "apps-e2e-only.list.session+credential";
        let inventory = json!({
            "ok": true,
            "caller": "apps-user",
            "scope": "publisher",
            "captured_at": "2026-09-01T12:00:00Z",
            "count": 1,
            "apps": [{
                "app_id": "merchant-lookup",
                "role": "publisher",
                "status": "deleted",
                "ready": false,
                "active_version_id": "ver-123",
                "last_published_by": "apps-user"
            }]
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(inventory.clone())]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "list",
                "--scope",
                "publisher",
                "--include-deleted",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps list process command");
        assert!(
            output.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_str::<Value>(&process_stdout(&output))
                .expect("parse list process output"),
            inventory
        );
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 1);
        assert_process_control_plane(
            &requests[0],
            "GET",
            "/v1/agent/apps?scope=publisher&include_deleted=true",
            credential,
        );
        assert_eq!(requests[0].body, Value::Null);
    }

    #[test]
    fn app_scoped_paths_are_requests_about_one_app() {
        for path in [
            "/v1/agent/apps/demo",
            "/v1/agent/apps/demo?environment=staging",
            "/v1/agent/apps/demo/access",
            "/v1/agent/apps/merchant%2Flookup%20app/deploy",
        ] {
            assert!(is_app_scoped_path(path), "{path}");
        }
        for path in [
            APPS_CONTRACT_PATH,
            APPS_PLAN_PATH,
            "/v1/agent/apps",
            "/v1/agent/apps?scope=owned",
            "/v1/agent/apps/",
        ] {
            assert!(!is_app_scoped_path(path), "{path}");
        }
    }

    #[test]
    fn bl_apps_generic_denial_asks_the_owner_only_for_an_app_request() {
        let credential = "apps-e2e-only.app-denial.session";
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::raw(403, "").with_trace_id(REQUEST_TRACE_ID)
        ]);
        let output = process_command(
            &auth_server,
            &control_plane,
            &["apps", "get", "demo", "--base-url", APPROVED_TEST_BASE_URL],
            credential,
        )
        .output()
        .expect("run app denial");
        assert_eq!(output.status.code(), Some(exit_codes::FORBIDDEN));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("Ask the app owner to confirm"), "{stderr}");
        assert!(!stderr.contains("bl workspace"), "{stderr}");
        auth_server.finish();
        assert_eq!(control_plane.finish()[0].path, "/v1/agent/apps/demo");
    }

    #[test]
    fn bl_apps_process_distinguishes_account_setup_from_other_denials() {
        let credential = "apps-e2e-only.account-access.session";
        let needs_details = json!({
            "account_status": "ACCOUNT_STATUS_NEEDS_DETAILS", "enabled_products": []
        });
        let cases = [
            (
                needs_details.clone(),
                403,
                "",
                "account_setup_required",
                "Finish account setup",
            ),
            (
                json!({"account_status": "ACCOUNT_STATUS_OK", "enabled_products": []}),
                403,
                "",
                "builderlab_access_required",
                "product access is not enabled",
            ),
            (
                json!({"enabled_products": []}),
                403,
                "",
                "builderlab_access_required",
                "product access is not enabled",
            ),
            (
                json!({"account_status": "ACCOUNT_STATUS_PENDING", "enabled_products": []}),
                403,
                "",
                "control_plane_request_failed",
                "and your workspace permissions.",
            ),
            (
                json!({"account_status": "ACCOUNT_STATUS_REJECTED", "enabled_products": []}),
                403,
                "",
                "control_plane_request_failed",
                "and your workspace permissions.",
            ),
            (
                json!({"account_status": "ACCOUNT_STATUS_FUTURE", "enabled_products": []}),
                403,
                "",
                "control_plane_request_failed",
                "and your workspace permissions.",
            ),
            (
                json!({}),
                403,
                "",
                "control_plane_request_failed",
                "and your workspace permissions.",
            ),
            (
                needs_details.clone(),
                403,
                r#"{"error":{"code":"owner_required"},"next_action":"Ask the app owner for access."}"#,
                "owner_required",
                "Ask the app owner",
            ),
            (
                needs_details,
                401,
                r#"{"error":{"code":"session_expired"}}"#,
                "session_expired",
                "replace your session",
            ),
        ];
        for (account_fields, status, body, code, guidance) in cases {
            for json_output in [false, true] {
                let mut auth_body: Value =
                    serde_json::from_str(&process_auth_response().body).unwrap();
                for (key, value) in account_fields.as_object().unwrap() {
                    auth_body[key] = value.clone();
                }
                // Legacy detail/reason fields and identity must never be copied
                // into recovery text, including for pending and unknown states.
                auth_body["account_standing"] = json!({"restriction_reason": "private-diagnostic"});
                let auth_server = ProcessServer::start(vec![ProcessResponse::json(auth_body)]);
                let control_plane = ProcessServer::start(vec![
                    ProcessResponse::raw(status, body).with_trace_id(REQUEST_TRACE_ID)
                ]);
                let mut args = vec!["apps", "list", "--base-url", APPROVED_TEST_BASE_URL];
                if json_output {
                    args.push("--json");
                }
                let output = process_command(&auth_server, &control_plane, &args, credential)
                    .output()
                    .expect("run account access denial");
                let expected_exit = if status == 401 {
                    exit_codes::AUTH_REQUIRED
                } else {
                    exit_codes::FORBIDDEN
                };
                assert_eq!(output.status.code(), Some(expected_exit));
                let stderr = String::from_utf8(output.stderr).unwrap();
                assert!(stderr.contains(guidance), "{stderr}");
                assert!(stderr.contains(REQUEST_TRACE_ID), "{stderr}");
                assert!(!stderr.contains(credential));
                assert!(!stderr.contains("private-diagnostic"));
                assert!(!stderr.contains("apps@example.com"));
                assert!(!stderr.contains("bl workspace switch"));
                assert!(!stderr.contains("bl workspace list"));
                // Listing apps has no app owner to ask.
                assert!(!stderr.contains("Ask the app owner to confirm"), "{stderr}");
                if code != "account_setup_required" {
                    assert!(!stderr.contains("Finish account setup"));
                }
                if json_output {
                    let payload = stderr
                        .lines()
                        .find_map(|line| serde_json::from_str::<Value>(line).ok())
                        .unwrap();
                    assert_eq!(payload["error"]["code"], code);
                    assert_eq!(payload["error"]["details"], json!({"http_status": status}));
                    assert_eq!(payload["error"]["trace_id"], REQUEST_TRACE_ID);
                    assert!(payload["next_action"].as_str().unwrap().contains(guidance));
                }
                let auth_requests = auth_server.finish();
                assert_eq!(auth_requests.len(), 1);
                assert_process_auth(&auth_requests[0], credential);
                let requests = control_plane.finish();
                assert_eq!(requests.len(), 1);
                assert_process_control_plane(&requests[0], "GET", "/v1/agent/apps", credential);
            }
        }
    }

    #[test]
    fn account_setup_links_use_only_known_web_origins() {
        for host in ["app.builderlab.xyz", "app.builderlabstaging.xyz"] {
            assert_eq!(
                account_setup_url(&format!("https://{host}/api/goose")),
                Some(format!("https://{host}/account/setup"))
            );
        }
        for base_url in [
            "https://kgoose.example.com",
            "http://app.builderlab.xyz",
            "https://app.builderlab.xyz:8443",
            "https://app.builderlab.xyz.example.com",
            "http://127.0.0.1:1234",
            "invalid",
        ] {
            assert!(account_setup_url(base_url).is_none());
        }
    }

    #[test]
    fn account_status_does_not_override_successful_apps_responses() {
        let mut auth_body: Value = serde_json::from_str(&process_auth_response().body).unwrap();
        auth_body["account_status"] = json!("ACCOUNT_STATUS_NEEDS_DETAILS");
        auth_body["enabled_products"] = json!([]);
        let auth_server = ProcessServer::start(vec![ProcessResponse::json(auth_body)]);
        let inventory = json!({"apps": []});
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(inventory.clone())]);
        let output = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "list",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--json",
            ],
            "apps-e2e-only.advisory.session",
        )
        .output()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_str::<Value>(&process_stdout(&output)).unwrap(),
            inventory
        );
        assert_eq!(auth_server.finish().len(), 1);
        assert_eq!(control_plane.finish().len(), 1);
    }

    #[test]
    fn bl_apps_owned_list_process_preserves_quota_without_deriving_usage() {
        let credential = "apps-e2e-only.quota-list.session+credential";
        for quota in [
            Some(json!({
                "accounting_enabled": true, "enforcement_enabled": true,
                "tier_status": "resolved", "tier": "example", "current_count": 7,
                "max_sites": 5, "remaining": 0, "over_limit": true
            })),
            Some(json!({
                "accounting_enabled": true, "enforcement_enabled": false,
                "tier_status": "resolved", "tier": "example", "current_count": 7,
                "max_sites": 5, "remaining": 0, "over_limit": true
            })),
            Some(json!({
                "accounting_enabled": true, "enforcement_enabled": true,
                "tier_status": "unavailable", "current_count": 7
            })),
            None,
        ] {
            let mut inventory = json!({
                "ok": true, "scope": "owned", "count": 1,
                "apps": [{"app_id": "merchant-lookup", "role": "owner"}]
            });
            if let Some(quota) = quota {
                inventory["quota"] = quota;
            }
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let control_plane =
                ProcessServer::start(vec![ProcessResponse::json(inventory.clone())]);
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "list",
                    "--scope",
                    "owned",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                    "--json",
                ],
                credential,
            )
            .output()
            .expect("run owned inventory command");
            assert!(output.status.success(), "{:?}", output);
            assert_eq!(
                serde_json::from_str::<Value>(&process_stdout(&output)).unwrap(),
                inventory
            );
            auth_server.finish();
            let requests = control_plane.finish();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].path, "/v1/agent/apps?scope=owned");
        }
    }

    #[test]
    fn bl_apps_handoff_process_is_read_only_without_workstation_login() {
        for (policy, expected_status, expected_reason) in [
            (
                ProcessResponse::json(
                    json!({"ok":true,"app_id":"demo","visibility":"restricted","viewers":[],"effective_viewers":["owner"],"shared_community_ids":["community"],"community_grant_revision":2}),
                ),
                "verified",
                Value::Null,
            ),
            (
                ProcessResponse::json(
                    json!({"ok":true,"app_id":"demo","visibility":"restricted","viewers":[],"effective_viewers":["owner"]}),
                ),
                "unknown",
                json!("incomplete_policy"),
            ),
            (
                ProcessResponse::json_status(
                    503,
                    json!({"error":{"code":"unavailable","message":"sensitive upstream detail"}}),
                ),
                "unknown",
                json!("unavailable"),
            ),
            (
                ProcessResponse::json_status(
                    401,
                    json!({"error":{"code":"identity_required","message":"sensitive upstream detail"}}),
                ),
                "unknown",
                json!("unauthenticated"),
            ),
            (
                ProcessResponse::json_status(
                    403,
                    json!({"error":{"code":"not_owner","message":"sensitive upstream detail"}}),
                ),
                "unknown",
                json!("forbidden"),
            ),
            (
                ProcessResponse::json_status(404, json!({"error":{"code":"app_not_found"}})),
                "unknown",
                json!("not_found"),
            ),
            (
                ProcessResponse::raw(200, "invalid JSON sensitive upstream detail"),
                "unknown",
                json!("request_failed"),
            ),
        ] {
            let auth = ProcessServer::start(vec![]);
            let control = ProcessServer::start(vec![
                ProcessResponse::json(
                    json!({"ok":true,"app":{"app_id":"demo","workspace_id":"owning-workspace","host":"demo.apps.example"}}),
                ),
                policy,
            ]);
            let output = process_command(
                &auth,
                &control,
                &[
                    "apps",
                    "handoff",
                    "demo",
                    "--management-base-url",
                    "https://app.builderlabstaging.xyz",
                    "--json",
                ],
                "apps-e2e-only.unused",
            )
            .env("BL_APPS_E2E_PROXY", "true")
            .env(APPS_BASE_URL_ENV_VAR, "http://compose.mesh.example")
            .output()
            .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let handoff: Value = serde_json::from_str(&process_stdout(&output)).unwrap();
            assert_eq!(
                handoff["management_url"],
                "https://app.builderlabstaging.xyz/hosted-apps?app=demo&workspace=owning-workspace"
            );
            assert_eq!(handoff["recipient_browser_access_verified"], false);
            assert_eq!(handoff["audience"]["status"], expected_status);
            assert_eq!(handoff["audience"]["reason"], expected_reason);
            assert!(handoff["next_action"]
                .as_str()
                .unwrap()
                .contains("Copying the link does not change access."));
            if expected_status == "unknown" {
                assert!(handoff["audience"]["policy"].is_null());
            } else {
                assert_eq!(
                    handoff["audience"]["policy"]["shared_community_ids"],
                    json!(["community"])
                );
            }
            assert!(!handoff.to_string().contains("sensitive upstream detail"));
            assert!(auth.finish().is_empty());
            let requests = control.finish();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[0].path, "/v1/agent/apps/demo");
            assert_eq!(requests[1].path, "/v1/agent/apps/demo/access");
            for request in requests {
                assert_eq!(request.method, "GET");
                for name in ["authorization", "cookie", "x-bb-session-credential"] {
                    assert!(!request.headers.contains_key(name));
                }
            }
        }
    }

    #[test]
    fn bl_apps_get_process_encodes_app_id_and_preserves_versions() {
        let credential = "apps-e2e-only.get.session+credential";
        let app = json!({
            "ok": true,
            "app": {
                "app_id": "merchant/lookup app",
                "environment": "staging",
                "role": "owner",
                "ready": true,
                "route_revision": 9
            },
            "versions": [{
                "version_id": "ver-123",
                "deployment_id": "dpl-123",
                "active": true
            }]
        });
        let access = json!({
            "ok": true,
            "app_id": "merchant/lookup app",
            "visibility": "organization",
            "viewers": [],
            "community_grant_revision": 0
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(app.clone()),
            ProcessResponse::json(access.clone()),
        ]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "get",
                "merchant/lookup app",
                "--environment",
                "staging",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps get process command");
        assert!(output.status.success());
        let got: Value =
            serde_json::from_str(&process_stdout(&output)).expect("parse get process output");
        // Inspection fields are unchanged; the audience is added beside them.
        for field in ["ok", "app", "versions"] {
            assert_eq!(got[field], app[field], "{field}");
        }
        assert_eq!(got["app_id"], "merchant/lookup app");
        assert_eq!(got["audience"]["status"], "verified");
        assert_eq!(got["audience"]["policy"], access);
        assert_eq!(got["who_can_open"], "Everyone in the app's workspace.");
        assert!(got["management_url"].is_null());
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_process_control_plane(
            &requests[0],
            "GET",
            "/v1/agent/apps/merchant%2Flookup%20app?environment=staging",
            credential,
        );
        assert_process_control_plane(
            &requests[1],
            "GET",
            "/v1/agent/apps/merchant%2Flookup%20app/access?environment=staging",
            credential,
        );
    }

    #[test]
    fn bl_apps_get_and_its_handoff_alias_print_the_same_readable_summary() {
        let credential = "apps-e2e-only.get-text.session";
        let mut outputs = Vec::new();
        for subcommand in ["get", "handoff"] {
            let auth_server = ProcessServer::start(vec![
                process_auth_response(),
                ProcessResponse::json(
                    json!({"communities":[{"id":"buzz-alpha","name":"Alpha Team"}]}),
                ),
            ]);
            let control_plane = ProcessServer::start(vec![
                ProcessResponse::json(json!({"ok":true,"app":{
                    "app_id":"hello","name":"Hello","role":"owner","workspace_id":"ws",
                    "host":"hello.apps.example","status":"running"
                }})),
                ProcessResponse::json(json!({
                    "ok":true,"app_id":"hello","owner":"auth0|apps-user","visibility":"restricted",
                    "viewers":["auth0|apps-user","auth0|old"],
                    "effective_viewers":["auth0|apps-user","auth0|old"],
                    "shared_community_ids":["buzz-alpha"],"community_grant_revision":2
                })),
            ]);
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    subcommand,
                    "hello",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                ],
                credential,
            )
            .env(
                MANAGEMENT_BASE_URL_ENV_VAR,
                "https://app.builderlabstaging.xyz",
            )
            .output()
            .expect("run Apps get text process");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let auth_requests = auth_server.finish();
            assert_eq!(auth_requests[1].method, "POST");
            assert_eq!(
                auth_requests[1].path,
                format!("/api/goose{JOINED_COMMUNITIES_PATH}")
            );
            assert_eq!(control_plane.finish().len(), 2);
            outputs.push(process_stdout(&output));
        }
        assert_eq!(
            outputs[0],
            "Hello (hello)\n\
             Open app: https://hello.apps.example/\n\
             Who can open it: Only you. 1 other person can also open it. So can members of the Buzz community Alpha Team.\n\
             Share & manage: https://app.builderlabstaging.xyz/hosted-apps?app=hello&workspace=ws\n\
             Status: running"
        );
        assert_eq!(outputs[0], outputs[1]);
    }

    #[test]
    fn bl_apps_visibility_and_community_print_who_can_open_without_json() {
        let credential = "apps-e2e-only.sharing-text.session";
        // When the Kgoose name lookup fails, communities are named by ID.
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(json!({
            "ok":true,"app_id":"my-app","owner":"auth0|apps-user","visibility":"organization",
            "viewers":["auth0|apps-user"],"shared_community_ids":["buzz-alpha"]
        }))]);
        let output = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "visibility",
                "my-app",
                "workspace",
                "--base-url",
                APPROVED_TEST_BASE_URL,
            ],
            credential,
        )
        .output()
        .expect("run visibility text process");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            process_stdout(&output),
            "Who can open my-app now: Everyone in the app's workspace. So can members of the Buzz community buzz-alpha."
        );
        auth_server.finish();
        control_plane.finish();

        let auth_server = ProcessServer::start(vec![
            process_auth_response(),
            ProcessResponse::json(json!({"communities":[{"id":"buzz-alpha","name":"Alpha Team"}]})),
        ]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(
                json!({"ok":true,"app_id":"my-app","lifecycle_id":"life-1","community_grant_revision":4}),
            ),
            ProcessResponse::json(
                json!({"ok":true,"app_id":"my-app","community_grant_revision":5,"shared_community_ids":null}),
            ),
        ]);
        let output = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "community",
                "revoke",
                "my-app",
                "buzz-alpha",
                "--base-url",
                APPROVED_TEST_BASE_URL,
            ],
            credential,
        )
        .output()
        .expect("run community revoke text process");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            process_stdout(&output),
            "my-app is no longer shared with the Buzz community Alpha Team.\n\
             Run `bl apps get my-app` to see everyone who can open it."
        );
        auth_server.finish();
        control_plane.finish();
    }

    #[test]
    fn bl_apps_access_process_gets_and_replaces_the_complete_policy() {
        let credential = "apps-e2e-only.access.session+credential";
        let current = json!({
            "ok": true,
            "app_id": "merchant/lookup app",
            "environment": "staging/west",
            "owner": "auth0|owner",
            "visibility": "restricted",
            "viewers": ["auth0|alice"],
            "effective_viewers": ["auth0|owner", "auth0|publisher", "auth0|alice"]
        });
        let updated = json!({
            "ok": true,
            "app_id": "merchant/lookup app",
            "environment": "staging/west",
            "owner": "auth0|owner",
            "visibility": "restricted",
            "viewers": ["auth0|bob", "auth0|carol"],
            "effective_viewers": ["auth0|owner", "auth0|publisher", "auth0|bob", "auth0|carol"]
        });
        let auth_server =
            ProcessServer::start(vec![process_auth_response(), process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(current.clone()),
            ProcessResponse::json(updated.clone()),
        ]);

        let mut get_command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "access",
                "get",
                "merchant/lookup app",
                "--environment",
                "staging/west",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );
        let get_output = get_command
            .output()
            .expect("run Apps access get process command");
        assert!(
            get_output.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&get_output.stderr)
        );
        assert_eq!(
            serde_json::from_str::<Value>(&process_stdout(&get_output))
                .expect("parse access get process output"),
            current
        );

        let mut set_command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "access",
                "set",
                "merchant/lookup app",
                "--visibility",
                "restricted",
                "--viewer",
                "auth0|bob",
                "--viewer",
                "auth0|carol",
                "--environment",
                "staging/west",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );
        let set_output = set_command
            .output()
            .expect("run Apps access set process command");
        assert!(
            set_output.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&set_output.stderr)
        );
        assert_eq!(
            serde_json::from_str::<Value>(&process_stdout(&set_output))
                .expect("parse access set process output"),
            updated
        );

        let auth_requests = auth_server.finish();
        assert_eq!(auth_requests.len(), 2);
        for request in &auth_requests {
            assert_process_auth(request, credential);
        }
        let requests = control_plane.finish();
        assert_eq!(requests.len(), 2);
        assert_process_control_plane(
            &requests[0],
            "GET",
            "/v1/agent/apps/merchant%2Flookup%20app/access?environment=staging%2Fwest",
            credential,
        );
        assert_eq!(requests[0].body, Value::Null);
        assert_process_control_plane(
            &requests[1],
            "PUT",
            "/v1/agent/apps/merchant%2Flookup%20app/access",
            credential,
        );
        assert_eq!(
            requests[1].body,
            json!({
                "visibility": "restricted",
                "viewers": ["auth0|bob", "auth0|carol"],
                "environment": "staging/west"
            })
        );
    }

    #[test]
    fn bl_apps_access_process_explicitly_clears_restricted_viewers() {
        let credential = "apps-e2e-only.access.clear.session+credential";
        let updated = json!({
            "ok": true,
            "app_id": "merchant-lookup",
            "environment": "production",
            "owner": "auth0|owner",
            "visibility": "restricted",
            "viewers": [],
            "effective_viewers": ["auth0|owner"]
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(updated.clone())]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "access",
                "set",
                "merchant-lookup",
                "--visibility",
                "restricted",
                "--clear-viewers",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command
            .output()
            .expect("run Apps access explicit viewer clearing command");
        assert!(
            output.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_str::<Value>(&process_stdout(&output))
                .expect("parse access clearing output"),
            updated
        );

        let auth_requests = auth_server.finish();
        assert_eq!(auth_requests.len(), 1);
        assert_process_auth(&auth_requests[0], credential);
        let requests = control_plane.finish();
        assert_eq!(requests.len(), 1);
        assert_process_control_plane(
            &requests[0],
            "PUT",
            "/v1/agent/apps/merchant-lookup/access",
            credential,
        );
        assert_eq!(
            requests[0].body,
            json!({"visibility": "restricted", "viewers": []})
        );
    }

    #[test]
    fn bl_apps_versions_process_preserves_rollback_candidates() {
        let credential = "apps-e2e-only.versions.session+credential";
        let versions = json!({
            "ok": true,
            "app_id": "merchant-lookup",
            "environment": "staging",
            "active_version_id": "ver-123",
            "count": 2,
            "versions": [
                {"version_id": "ver-123", "route_revision": 9, "active": true},
                {"version_id": "ver-122", "route_revision": 8, "active": false}
            ]
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(versions.clone())]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "versions",
                "merchant-lookup",
                "--environment",
                "staging",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps versions process command");
        assert!(output.status.success());
        assert_eq!(
            serde_json::from_str::<Value>(&process_stdout(&output))
                .expect("parse versions process output"),
            versions
        );
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_process_control_plane(
            &requests[0],
            "GET",
            "/v1/agent/apps/merchant-lookup/versions?environment=staging",
            credential,
        );
    }

    #[test]
    fn bl_apps_create_server_runs_plan_reserve_and_initialize() {
        for (persistence, profile) in [
            ("sqlite", "fetch-js"),
            ("mysql", "process"),
            ("mysql", "fetch-js"),
        ] {
            let credential = "apps-e2e-only.create.session+credential";
            let plan = json!({
                "app_id": "merchant-lookup",
                "display_name": "Merchant Lookup",
                "environment": "staging",
                "persistence": persistence,
                "runtime_profile": profile,
                "runtime_class": "default",
                "initialize": {"required": true, "recommended": false}
            });
            let initialized = json!({
                "app_id": "merchant-lookup",
                "external_url": "https://merchant-lookup--bpsites.example/",
                "persistence": persistence
            });
            let reservation = json!({
                "app_id": "merchant-lookup",
                "external_url": "https://merchant-lookup--bpsites.example/"
            });
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let control_plane = ProcessServer::start(vec![
                ProcessResponse::json(plan.clone()),
                ProcessResponse::json(reservation.clone()),
                ProcessResponse::json(initialized.clone()),
            ]);
            let mut command = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "create",
                    "--app-id",
                    "merchant-lookup",
                    "--name",
                    "Merchant Lookup",
                    "--environment",
                    "staging",
                    "--runtime-profile",
                    profile,
                    "--persistence",
                    persistence,
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                    "--client-version",
                    "0.2.0",
                    "--json",
                ],
                credential,
            );

            let output = command.output().expect("run Apps create process command");
            assert!(
                output.status.success(),
                "stderr was: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let value = serde_json::from_str::<Value>(&process_stdout(&output))
                .expect("parse create process output");
            assert_eq!(value["app_id"], "merchant-lookup");
            assert_eq!(value["reserved"], true);
            assert_eq!(value["initialized"], true);
            assert_eq!(value["plan"], plan);
            assert_eq!(value["reservation"], reservation);
            assert_eq!(value["visibility"], Value::Null);
            assert_eq!(value["initialize"], initialized);
            let auth_requests = auth_server.finish();
            let requests = control_plane.finish();
            assert_process_auth(&auth_requests[0], credential);
            assert_eq!(requests.len(), 3);
            assert_process_control_plane(&requests[0], "POST", APPS_PLAN_PATH, credential);
            assert_eq!(
                requests[0].body,
                json!({
                    "app_id": "merchant-lookup",
                    "name": "Merchant Lookup",
                    "environment": "staging",
                    "runtime_profile": profile,
                    "persistence": persistence,
                    "client_version": "0.2.0"
                })
            );
            assert_process_control_plane(
                &requests[1],
                "POST",
                "/v1/agent/apps/merchant-lookup/reserve",
                credential,
            );
            assert_eq!(
                requests[1].body,
                json!({
                    "environment": "staging",
                    "persistence": persistence,
                "runtime_profile": profile,
                    "runtime_class": "default",
                    "name": "Merchant Lookup"
                })
            );
            assert_process_control_plane(
                &requests[2],
                "POST",
                "/v1/agent/apps/merchant-lookup/initialize",
                credential,
            );
            assert_eq!(requests[2].body, requests[1].body);
        }
    }

    #[test]
    fn bl_apps_mysql_requires_explicit_server_runtime_before_authentication() {
        for subcommand in ["create", "initialize"] {
            for profile in [None, Some("static"), Some("unknown")] {
                let mut args = vec!["apps", subcommand];
                if subcommand == "create" {
                    args.push("--app-id");
                }
                args.extend([
                    "mysql-app",
                    "--persistence",
                    "mysql",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                ]);
                if let Some(profile) = profile {
                    args.extend(["--runtime-profile", profile]);
                }
                let matches = command()
                    .try_get_matches_from(args)
                    .expect("parse mysql command");
                let (_, args) = matches.subcommand().unwrap();
                let error = validate_mysql_runtime(args).unwrap_err();
                assert!(error
                    .to_string()
                    .contains("requires --runtime-profile process or fetch-js"));
            }
        }
    }

    #[test]
    fn bl_apps_create_mysql_rejects_unsafe_plan_before_reservation() {
        for requested_profile in ["process", "fetch-js"] {
            for (persistence, profile, initialize) in [
                (Some("sqlite"), Some("process"), true),
                (None, Some("process"), true),
                (
                    Some("mysql"),
                    Some(if requested_profile == "process" {
                        "fetch-js"
                    } else {
                        "process"
                    }),
                    true,
                ),
                (Some("mysql"), Some("static"), true),
                (Some("mysql"), None, true),
                (Some("mysql"), Some(requested_profile), false),
            ] {
                let auth_server = ProcessServer::start(vec![process_auth_response()]);
                let control_plane = ProcessServer::start(vec![ProcessResponse::json(json!({
                    "app_id": "mysql-app", "persistence": persistence, "runtime_profile": profile,
                    "initialize": {"required": initialize, "recommended": false}
                }))]);
                let output = process_command(
                    &auth_server,
                    &control_plane,
                    &[
                        "apps",
                        "create",
                        "--app-id",
                        "mysql-app",
                        "--persistence",
                        "mysql",
                        "--runtime-profile",
                        requested_profile,
                        "--base-url",
                        APPROVED_TEST_BASE_URL,
                        "--json",
                    ],
                    "apps-e2e-only.mysql-plan",
                )
                .output()
                .unwrap();
                assert!(!output.status.success());
                assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to reserve"));
                auth_server.finish();
                let requests = control_plane.finish();
                assert_eq!(requests.len(), 1);
                assert_eq!(requests[0].path, APPS_PLAN_PATH);
            }
        }
    }

    #[test]
    fn bl_apps_create_mysql_preserves_server_rejections_without_fallback() {
        for requested_profile in ["process", "fetch-js"] {
            for (failed_stage, code) in [(0, "mysql_unavailable"), (2, "mysql_not_ready")] {
                let plan = ProcessResponse::json(json!({
                    "app_id": "mysql-app", "persistence": "mysql", "runtime_profile": requested_profile,
                    "environment": "staging", "initialize": {"required": true, "recommended": true}
                }));
                let failure = ProcessResponse::json_status(
                    409,
                    json!({
                        "ok": false, "error": {"code": code, "message": "private provider diagnostic"},
                        "next_action": "Inspect this app on the selected control plane."
                    }),
                );
                let responses = if failed_stage == 0 {
                    vec![failure]
                } else {
                    vec![
                        plan,
                        ProcessResponse::json(json!({"app_id":"mysql-app"})),
                        failure,
                    ]
                };
                let auth_server = ProcessServer::start(vec![process_auth_response()]);
                let control_plane = ProcessServer::start(responses);
                let credential = "apps-e2e-only.mysql-failure";
                let output = process_command(
                    &auth_server,
                    &control_plane,
                    &[
                        "apps",
                        "create",
                        "--app-id",
                        "mysql-app",
                        "--persistence",
                        "mysql",
                        "--runtime-profile",
                        requested_profile,
                        "--base-url",
                        APPROVED_TEST_BASE_URL,
                        "--json",
                    ],
                    credential,
                )
                .output()
                .unwrap();
                assert!(!output.status.success());
                let error = process_error(&output);
                assert_eq!(error["error"]["code"], code);
                assert!(error["next_action"]
                    .as_str()
                    .unwrap()
                    .contains("selected control plane"));
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(!stderr.contains("private provider diagnostic"));
                assert!(!stderr.contains(credential));
                if failed_stage == 2 {
                    assert!(stderr.contains(&format!("--runtime-profile {requested_profile}")));
                }
                auth_server.finish();
                let requests = control_plane.finish();
                assert_eq!(
                    requests.len(),
                    failed_stage + 1,
                    "no retries or sqlite fallback"
                );
            }
        }
    }

    #[test]
    fn bl_apps_create_mysql_requires_initialization_to_confirm_persistence() {
        for requested_profile in ["process", "fetch-js"] {
            for persistence in [None, Some("sqlite")] {
                let auth_server = ProcessServer::start(vec![process_auth_response()]);
                let control_plane = ProcessServer::start(vec![
                    ProcessResponse::json(json!({"app_id":"mysql-app", "persistence":"mysql",
                    "runtime_profile":requested_profile, "initialize":{"required":true,"recommended":false}})),
                    ProcessResponse::json(json!({"app_id":"mysql-app"})),
                    ProcessResponse::json(json!({"app_id":"mysql-app", "persistence":persistence,
                    "external_url":"https://mysql-app.example/"})),
                ]);
                let output = process_command(
                    &auth_server,
                    &control_plane,
                    &[
                        "apps",
                        "create",
                        "--app-id",
                        "mysql-app",
                        "--persistence",
                        "mysql",
                        "--runtime-profile",
                        requested_profile,
                        "--base-url",
                        APPROVED_TEST_BASE_URL,
                        "--json",
                    ],
                    "apps-e2e-only.mysql-confirm",
                )
                .output()
                .unwrap();
                assert!(!output.status.success());
                assert!(String::from_utf8_lossy(&output.stderr)
                    .contains("did not confirm mysql persistence"));
                auth_server.finish();
                assert_eq!(control_plane.finish().len(), 3);
            }
        }
    }

    #[test]
    fn bl_apps_initialize_mysql_plans_and_repairs_existing_app_without_reserve() {
        for requested_profile in ["process", "fetch-js"] {
            for recommended in [false, true] {
                let auth_server = ProcessServer::start(vec![process_auth_response()]);
                let control_plane = ProcessServer::start(vec![
                    ProcessResponse::json(
                        json!({"ok":true,"app":{"app_id":"mysql-app","persistence":"mysql","status":"active"}}),
                    ),
                    ProcessResponse::json(json!({"app_id":"mysql-app","environment":"staging",
                    "persistence":"mysql","runtime_profile":requested_profile,
                    "initialize":{"required":false,"recommended":recommended}})),
                    ProcessResponse::json(json!({"app_id":"mysql-app","persistence":"mysql",
                    "external_url":"https://mysql-app.example/"})),
                ]);
                let output = process_command(
                    &auth_server,
                    &control_plane,
                    &[
                        "apps",
                        "initialize",
                        "mysql-app",
                        "--environment",
                        "staging",
                        "--persistence",
                        "mysql",
                        "--runtime-profile",
                        requested_profile,
                        "--base-url",
                        APPROVED_TEST_BASE_URL,
                        "--json",
                    ],
                    "apps-e2e-only.mysql-initialize",
                )
                .output()
                .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let response: Value = serde_json::from_str(&process_stdout(&output)).unwrap();
                assert_eq!(response["initialized"], true);
                assert_eq!(response["initialize"]["persistence"], "mysql");
                auth_server.finish();
                let requests = control_plane.finish();
                assert_eq!(requests.len(), 3);
                assert_eq!(requests[0].method, "GET");
                assert_eq!(
                    requests[0].path,
                    "/v1/agent/apps/mysql-app?environment=staging"
                );
                assert_eq!(requests[1].path, APPS_PLAN_PATH);
                assert_eq!(requests[1].body["persistence"], "mysql");
                assert_eq!(requests[1].body["runtime_profile"], requested_profile);
                assert_eq!(requests[2].path, "/v1/agent/apps/mysql-app/initialize");
                assert_eq!(
                    requests[2].body,
                    json!({"environment":"staging",
                "runtime_profile":requested_profile,"persistence":"mysql"})
                );
            }
        }
    }

    #[test]
    fn bl_apps_initialize_rejects_missing_deleted_or_substituted_app_before_plan() {
        for existing in [
            ProcessResponse::json_status(404, json!({"error":{"code":"app_not_found"}})),
            ProcessResponse::json(json!({"app":{"app_id":"mysql-app","status":"deleted"}})),
            ProcessResponse::json(
                json!({"app":{"app_id":"mysql-app","deleted_at":"2026-01-01T00:00:00Z"}}),
            ),
            ProcessResponse::json(json!({"app":{"app_id":"another-app"}})),
        ] {
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let control_plane = ProcessServer::start(vec![existing]);
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "initialize",
                    "mysql-app",
                    "--persistence",
                    "mysql",
                    "--runtime-profile",
                    "process",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                    "--json",
                ],
                "apps-e2e-only.mysql-initialize-stop",
            )
            .output()
            .unwrap();
            assert!(!output.status.success());
            auth_server.finish();
            let requests = control_plane.finish();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].method, "GET");
        }
    }

    #[test]
    fn bl_apps_initialize_mysql_rejects_changed_plan_before_mutation() {
        for requested_profile in ["process", "fetch-js"] {
            let other_profile = if requested_profile == "process" {
                "fetch-js"
            } else {
                "process"
            };
            for (persistence, profile) in [
                (Some("sqlite"), Some(requested_profile)),
                (None, Some(requested_profile)),
                (Some("mysql"), Some(other_profile)),
                (Some("mysql"), Some("static")),
                (Some("mysql"), None),
            ] {
                let auth_server = ProcessServer::start(vec![process_auth_response()]);
                let control_plane = ProcessServer::start(vec![
                    ProcessResponse::json(json!({"app":{"app_id":"mysql-app"}})),
                    ProcessResponse::json(
                        json!({"app_id":"mysql-app", "persistence":persistence,"runtime_profile":profile}),
                    ),
                ]);
                let output = process_command(
                    &auth_server,
                    &control_plane,
                    &[
                        "apps",
                        "initialize",
                        "mysql-app",
                        "--persistence",
                        "mysql",
                        "--runtime-profile",
                        requested_profile,
                        "--base-url",
                        APPROVED_TEST_BASE_URL,
                        "--json",
                    ],
                    "apps-e2e-only.mysql-initialize-changed-plan",
                )
                .output()
                .unwrap();
                assert!(!output.status.success());
                assert!(String::from_utf8_lossy(&output.stderr)
                    .contains("refusing to reserve or initialize"));
                auth_server.finish();
                assert_eq!(control_plane.finish().len(), 2);
            }
        }
    }

    #[test]
    fn incomplete_reservation_with_another_runtime_cannot_be_adopted() {
        let existing = json!({"ok":true,"app":{"app_id":"mysql-app","role":"owner",
            "route_status":"idle","route_revision":1,"runtime_profile":"static"},"versions":[]});
        assert!(!is_matching_incomplete_reservation(
            &existing,
            "mysql-app",
            &json!({"runtime_profile":"process"})
        ));
    }

    #[test]
    fn bl_apps_create_process_preserves_quota_rejection_without_mutation_retry() {
        let credential = "apps-e2e-only.quota-create.session+credential";
        let details = json!({
            "tier": "example", "current_count": 7, "max_sites": 5,
            "remaining": 0, "owned_sites_url": "/v1/apps/owned"
        });
        let next_action = "Review owned sites before explicitly retrying.";
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(json!({
                "app_id": "merchant-lookup",
                "environment": "staging",
                "initialize": {"required": true, "recommended": false}
            })),
            ProcessResponse::json_status(
                409,
                json!({
                    "ok": false,
                    "error": {
                        "code": "owner_site_limit_reached",
                        "message": "provider diagnostics must not reach the CLI",
                        "details": details
                    },
                    "next_action": next_action
                }),
            ),
            ProcessResponse::json_status(
                404,
                json!({
                    "ok": false,
                    "error": {"code": "app_not_found"}
                }),
            ),
        ]);
        let output = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "create",
                "--app-id",
                "merchant-lookup",
                "--environment",
                "staging",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--json",
            ],
            credential,
        )
        .output()
        .expect("run quota-rejected create");
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        let payload = stderr
            .lines()
            .find_map(|line| serde_json::from_str::<Value>(line).ok())
            .expect("structured CLI error on stderr");
        assert_eq!(payload["error"]["code"], "owner_site_limit_reached");
        let mut expected_details = details;
        expected_details["http_status"] = json!(409);
        assert_eq!(payload["error"]["details"], expected_details);
        assert_eq!(payload["next_action"], next_action);
        assert!(!stderr.contains("provider diagnostics"));
        assert!(!stderr.contains(credential));
        auth_server.finish();
        let requests = control_plane.finish();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].path, "/v1/agent/apps/merchant-lookup/reserve");
        assert_eq!(requests[1].method, "POST");
        assert_eq!(requests[2].method, "GET");
        assert_eq!(
            requests[2].path,
            "/v1/agent/apps/merchant-lookup?environment=staging"
        );
    }

    #[test]
    fn bl_apps_create_requires_complete_boolean_initialize_decision_before_reserve() {
        let credential = "apps-e2e-only.initialize-decision.session+credential";
        let valid_plan = json!({
            "app_id": "merchant-lookup",
            "display_name": "Merchant Lookup",
            "environment": "staging",
            "persistence": "none",
            "runtime_class": "default",
            "initialize": {"required": false, "recommended": false}
        });

        for field in ["required", "recommended"] {
            for (shape, replacement) in [
                ("missing", None),
                ("null", Some(Value::Null)),
                ("non-boolean", Some(Value::String("false".to_string()))),
            ] {
                let mut plan = valid_plan.clone();
                let initialize = plan["initialize"]
                    .as_object_mut()
                    .expect("initialize object");
                match replacement {
                    Some(value) => {
                        initialize.insert(field.to_string(), value);
                    }
                    None => {
                        initialize.remove(field);
                    }
                }
                let auth_server = ProcessServer::start(vec![process_auth_response()]);
                let control_plane = ProcessServer::start(vec![ProcessResponse::json(plan)]);
                let mut command = process_command(
                    &auth_server,
                    &control_plane,
                    &[
                        "apps",
                        "create",
                        "--app-id",
                        "merchant-lookup",
                        "--name",
                        "Merchant Lookup",
                        "--base-url",
                        APPROVED_TEST_BASE_URL,
                        "--client-version",
                        "0.2.0",
                        "--json",
                    ],
                    credential,
                );

                let output = command
                    .output()
                    .unwrap_or_else(|error| panic!("run create with {field} {shape}: {error}"));
                assert!(
                    !output.status.success(),
                    "accepted initialize.{field} as {shape}"
                );
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    stderr.contains(&format!("boolean initialize.{field}"))
                        && stderr.contains("refusing to reserve the app"),
                    "stderr for initialize.{field} as {shape} was: {stderr}"
                );
                let auth_requests = auth_server.finish();
                let requests = control_plane.finish();
                assert_process_auth(&auth_requests[0], credential);
                assert_eq!(
                    requests.len(),
                    1,
                    "initialize.{field} as {shape} sent a mutation"
                );
                assert_process_control_plane(&requests[0], "POST", APPS_PLAN_PATH, credential);
            }
        }
    }

    #[test]
    fn bl_apps_create_requires_descriptive_identity() {
        let error = command()
            .try_get_matches_from(["apps", "create", "--base-url", APPROVED_TEST_BASE_URL])
            .expect_err("create without app identity must fail");

        assert!(error
            .to_string()
            .contains("--app-id <APP_ID>|--name <NAME>"));
    }

    #[test]
    fn bl_apps_create_rejects_empty_identity() {
        for argument in ["--app-id", "--name"] {
            command()
                .try_get_matches_from([
                    "apps",
                    "create",
                    argument,
                    "",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                ])
                .expect_err("empty app identity must fail");
        }
    }

    #[test]
    fn bl_apps_create_rejects_plan_substitute_before_initialize() {
        let credential = "apps-e2e-only.plan-substitute.session+credential";
        let plan = json!({
            "app_id": "merchant-lookup-2",
            "initialize": {"required": true, "recommended": true}
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(plan)]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "create",
                "--app-id",
                "merchant-lookup",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps create process command");
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(
            "expected exact app_id \\\"merchant-lookup\\\". No replacement app was accepted"
        ));
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 1);
        assert_process_control_plane(&requests[0], "POST", APPS_PLAN_PATH, credential);
    }

    #[test]
    fn bl_apps_create_rejects_reservation_substitute_before_initialize() {
        let credential = "apps-e2e-only.reserve-substitute.session+credential";
        let plan = json!({
            "app_id": "merchant-lookup",
            "display_name": "Merchant Lookup",
            "environment": "staging",
            "persistence": "none",
            "runtime_class": "default",
            "initialize": {"required": true, "recommended": true}
        });
        let reservation = json!({
            "app_id": "merchant-lookup-2",
            "external_url": "https://merchant-lookup-2--bpsites.example/"
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(plan),
            ProcessResponse::json(reservation),
        ]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "create",
                "--app-id",
                "merchant-lookup",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps create process command");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(
                "Apps Platform reserve returned app_id \\\"merchant-lookup-2\\\"; expected exact app_id \\\"merchant-lookup\\\". No replacement app was accepted"
            ),
            "stderr was: {stderr}"
        );
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 2);
        assert_process_control_plane(&requests[0], "POST", APPS_PLAN_PATH, credential);
        assert_process_control_plane(
            &requests[1],
            "POST",
            "/v1/agent/apps/merchant-lookup/reserve",
            credential,
        );
    }

    #[test]
    fn bl_apps_create_stops_on_reservation_collision() {
        let credential = "apps-e2e-only.reserve-collision.session+credential";
        let plan = json!({
            "app_id": "merchant-lookup",
            "display_name": "Merchant Lookup",
            "environment": "staging",
            "persistence": "none",
            "runtime_class": "default",
            "initialize": {"required": true, "recommended": true}
        });
        let collision = ProcessResponse::json_status(
            409,
            json!({
                "ok": false,
                "error": {
                    "code": "app_id_collision",
                    "message": "app_id is already reserved"
                }
            }),
        );
        let not_owned = ProcessResponse::json_status(
            403,
            json!({
                "ok": false,
                "error": {"code": "owner_required", "message": "caller does not own app"}
            }),
        );
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane =
            ProcessServer::start(vec![ProcessResponse::json(plan), collision, not_owned]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "create",
                "--app-id",
                "merchant-lookup",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps create process command");
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("app_id_collision"));
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 3);
        assert_process_control_plane(&requests[0], "POST", APPS_PLAN_PATH, credential);
        assert_process_control_plane(
            &requests[1],
            "POST",
            "/v1/agent/apps/merchant-lookup/reserve",
            credential,
        );
        assert_process_control_plane(
            &requests[2],
            "GET",
            "/v1/agent/apps/merchant-lookup?environment=staging",
            credential,
        );
    }

    #[test]
    fn bl_apps_create_retries_matching_reservation_after_initialize_failure() {
        let credential = "apps-e2e-only.resume-after-initialize.session+credential";
        let initial_plan = json!({
            "app_id": "merchant-lookup",
            "display_name": "Merchant Lookup",
            "environment": "staging",
            "persistence": "none",
            "runtime_class": "default",
            "runtime_profile": "process",
            "external_url": "https://merchant-lookup--bpsites.example/",
            "initialize": {"required": true, "recommended": true}
        });
        let retry_plan = json!({
            "app_id": "merchant-lookup",
            "display_name": "Merchant Lookup",
            "environment": "staging",
            "persistence": "none",
            "runtime_class": "default",
            "runtime_profile": "process",
            "external_url": "https://merchant-lookup--bpsites.example/",
            "initialize": {
                "required": true,
                "recommended": true,
                "reason": "the app ID is reserved, but its dynamic stack has not been initialized"
            }
        });
        let reservation = json!({
            "app_id": "merchant-lookup",
            "external_url": "https://merchant-lookup--bpsites.example/"
        });
        let initialize_failure = ProcessResponse::json_status(
            502,
            json!({
                "ok": false,
                "error": {"code": "kubernetes_apply_failed", "message": "runner rollout failed"}
            }),
        );
        let collision = ProcessResponse::json_status(
            409,
            json!({
                "ok": false,
                "error": {"code": "app_id_collision", "message": "app_id is already reserved"}
            }),
        );
        let existing_reservation = json!({
            "ok": true,
            "app": {
                "app_id": "merchant-lookup",
                "name": "Merchant Lookup",
                "environment": "staging",
                "persistence": "none",
                "runtime_class": "default",
                "role": "owner",
                "runtime_profile": "process",
                "status": "idle",
                "route_status": "idle",
                "route_revision": 1
            },
            "versions": []
        });
        let initialized = json!({
            "app_id": "merchant-lookup",
            "external_url": "https://merchant-lookup--bpsites.example/"
        });
        let auth_server =
            ProcessServer::start(vec![process_auth_response(), process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(initial_plan),
            ProcessResponse::json(reservation),
            initialize_failure,
            ProcessResponse::json(retry_plan),
            collision,
            ProcessResponse::json(existing_reservation),
            ProcessResponse::json(initialized.clone()),
        ]);
        let args = [
            "apps",
            "create",
            "--app-id",
            "merchant-lookup",
            "--name",
            "Merchant Lookup",
            "--runtime-profile",
            "process",
            "--base-url",
            APPROVED_TEST_BASE_URL,
            "--client-version",
            "0.2.0",
            "--json",
        ];

        let first = process_command(&auth_server, &control_plane, &args, credential)
            .output()
            .expect("run initial Apps create process command");
        assert!(!first.status.success());
        assert!(
            String::from_utf8_lossy(&first.stderr)
                .contains("Retry the same `bl apps create` command"),
            "stderr was: {}",
            String::from_utf8_lossy(&first.stderr)
        );

        let retry = process_command(&auth_server, &control_plane, &args, credential)
            .output()
            .expect("retry Apps create process command");
        assert!(
            retry.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&retry.stderr)
        );
        let value = serde_json::from_str::<Value>(&process_stdout(&retry))
            .expect("parse resumed create output");
        assert_eq!(value["app_id"], "merchant-lookup");
        assert_eq!(value["reservation_reconciled"], true);
        assert_eq!(value["initialized"], true);
        assert_eq!(value["initialize"], initialized);

        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_eq!(auth_requests.len(), 2);
        assert_eq!(requests.len(), 7);
        assert_process_control_plane(
            &requests[4],
            "POST",
            "/v1/agent/apps/merchant-lookup/reserve",
            credential,
        );
        assert_process_control_plane(
            &requests[5],
            "GET",
            "/v1/agent/apps/merchant-lookup?environment=staging",
            credential,
        );
        assert_process_control_plane(
            &requests[6],
            "POST",
            "/v1/agent/apps/merchant-lookup/initialize",
            credential,
        );
    }

    #[test]
    fn bl_apps_create_reconciles_committed_reservation_after_unreadable_response() {
        let credential = "apps-e2e-only.reserve-response-lost.session+credential";
        let plan = json!({
            "app_id": "merchant-lookup",
            "display_name": "Merchant Lookup",
            "environment": "staging",
            "persistence": "none",
            "runtime_class": "default",
            "runtime_profile": "process",
            "external_url": "https://merchant-lookup--bpsites.example/",
            "initialize": {"required": true, "recommended": true}
        });
        let existing_reservation = json!({
            "ok": true,
            "app": {
                "app_id": "merchant-lookup",
                "name": "Merchant Lookup",
                "environment": "staging",
                "persistence": "none",
                "runtime_class": "default",
                "role": "owner",
                "runtime_profile": "process",
                "status": "idle",
                "route_status": "idle",
                "route_revision": 1
            },
            "versions": []
        });
        let initialized = json!({
            "app_id": "merchant-lookup",
            "external_url": "https://merchant-lookup--bpsites.example/"
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(plan),
            ProcessResponse::raw(201, "{").with_trace_id(DEPLOYMENT_TRACE_ID),
            ProcessResponse::json(existing_reservation).with_trace_id(REQUEST_TRACE_ID),
            ProcessResponse::json(initialized),
        ]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "create",
                "--app-id",
                "merchant-lookup",
                "--name",
                "Merchant Lookup",
                "--runtime-profile",
                "process",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps create process command");
        assert!(
            output.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value = serde_json::from_str::<Value>(&process_stdout(&output))
            .expect("parse reconciled create output");
        assert_eq!(value["reservation_reconciled"], true);
        assert_eq!(value["reservation"]["trace_id"], REQUEST_TRACE_ID);
        assert_eq!(
            value["reservation"]["reserve_trace_id"],
            DEPLOYMENT_TRACE_ID
        );
        assert_eq!(value["initialized"], true);
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 4);
        assert_process_control_plane(
            &requests[2],
            "GET",
            "/v1/agent/apps/merchant-lookup?environment=staging",
            credential,
        );
        assert_process_control_plane(
            &requests[3],
            "POST",
            "/v1/agent/apps/merchant-lookup/initialize",
            credential,
        );
    }

    #[test]
    fn bl_apps_create_reconciles_reserve_only_plan_without_initialize() {
        let credential = "apps-e2e-only.reserve-only-reconcile.session+credential";
        let plan = json!({
            "app_id": "artifact-only-app",
            "display_name": "Artifact Only App",
            "environment": "staging",
            "persistence": "none",
            "runtime_class": "default",
            "runtime_profile": "fetch-js",
            "external_url": "https://artifact-only-app--bpsites.example/",
            "initialize": {"required": false, "recommended": false}
        });
        let existing_reservation = json!({
            "ok": true,
            "app": {
                "app_id": "artifact-only-app",
                "name": "Artifact Only App",
                "environment": "staging",
                "persistence": "none",
                "runtime_class": "default",
                "role": "owner",
                "runtime_profile": "fetch-js",
                "status": "idle",
                "route_status": "idle",
                "route_revision": 1
            },
            "versions": []
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(plan),
            ProcessResponse::raw(201, "{"),
            ProcessResponse::json(existing_reservation).with_trace_id(REQUEST_TRACE_ID),
        ]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "create",
                "--app-id",
                "artifact-only-app",
                "--name",
                "Artifact Only App",
                "--runtime-profile",
                "fetch-js",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command
            .output()
            .expect("run reserve-only create process command");
        assert!(
            output.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value = serde_json::from_str::<Value>(&process_stdout(&output))
            .expect("parse reconciled reserve-only output");
        assert_eq!(value["reservation_reconciled"], true);
        assert_eq!(value["reservation"]["trace_id"], REQUEST_TRACE_ID);
        assert_eq!(value["initialized"], false);
        assert_eq!(value["initialize"], Value::Null);
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 3);
        assert_process_control_plane(
            &requests[2],
            "GET",
            "/v1/agent/apps/artifact-only-app?environment=staging",
            credential,
        );
    }

    #[test]
    fn matching_incomplete_reservation_requires_authoritative_empty_state() {
        let mutation_request = json!({
            "name": "Merchant Lookup",
            "environment": "staging",
            "persistence": "none",
            "runtime_class": "default"
        });
        let response = json!({
            "ok": true,
            "app": {
                "app_id": "merchant-lookup",
                "name": "Merchant Lookup",
                "environment": "staging",
                "persistence": "none",
                "runtime_class": "default",
                "role": "owner",
                "route_status": "idle",
                "route_revision": 1
            },
            "versions": []
        });
        assert!(is_matching_incomplete_reservation(
            &response,
            "merchant-lookup",
            &mutation_request
        ));

        for invalid_versions in [Value::Null, json!({}), json!([{"version_id": "ver-1"}])] {
            let mut invalid = response.clone();
            invalid["versions"] = invalid_versions;
            assert!(!is_matching_incomplete_reservation(
                &invalid,
                "merchant-lookup",
                &mutation_request
            ));
        }
        let mut missing_versions = response.clone();
        missing_versions
            .as_object_mut()
            .expect("response object")
            .remove("versions");
        assert!(!is_matching_incomplete_reservation(
            &missing_versions,
            "merchant-lookup",
            &mutation_request
        ));

        for field in ["active_version_id", "version_id", "deleted_at"] {
            let mut malformed = response.clone();
            malformed["app"][field] = json!({});
            assert!(!is_matching_incomplete_reservation(
                &malformed,
                "merchant-lookup",
                &mutation_request
            ));
        }
    }

    #[test]
    fn bl_apps_create_retains_inspection_id_on_reservation_mismatch() {
        for reserve_trace_id in [None, Some(DEPLOYMENT_TRACE_ID)] {
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let mut reserve = ProcessResponse::raw(201, "{");
            if let Some(trace_id) = reserve_trace_id {
                reserve = reserve.with_trace_id(trace_id);
            }
            let control_plane = ProcessServer::start(vec![
                ProcessResponse::json(json!({
                    "app_id": "app",
                    "initialize": {"required": false, "recommended": false}
                })),
                reserve,
                ProcessResponse::json(json!({
                    "ok": true,
                    "app": {"app_id": "app", "role": "publisher"},
                    "versions": []
                }))
                .with_trace_id(REQUEST_TRACE_ID),
            ]);
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "create",
                    "--app-id",
                    "app",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                    "--client-version",
                    "0.2.0",
                    "--json",
                ],
                "apps-e2e-only.reservation-mismatch.trace",
            )
            .output()
            .expect("run create with mismatched inspected reservation");
            let payload = process_error(&output);
            assert_eq!(payload["error"]["code"], "reservation_outcome_unknown");
            assert_eq!(payload["error"]["exit_code"], exit_codes::NETWORK);
            assert_eq!(
                payload["error"]["trace_id"],
                reserve_trace_id.unwrap_or(REQUEST_TRACE_ID)
            );
            let message = payload["error"]["message"].as_str().unwrap();
            assert!(message.contains(&format!("trace_id={REQUEST_TRACE_ID}")));
            assert!(message.contains("not the same caller-owned, incomplete reservation"));
            auth_server.finish();
            assert_eq!(
                control_plane.finish().len(),
                3,
                "do not initialize a mismatched reservation"
            );
        }
    }

    #[test]
    fn bl_apps_create_reports_unknown_reservation_outcome_when_inspection_fails() {
        let credential = "apps-e2e-only.reserve-outcome-unknown.session+credential";
        let plan = json!({
            "app_id": "merchant-lookup",
            "display_name": "Merchant Lookup",
            "environment": "staging",
            "persistence": "none",
            "runtime_class": "default",
            "runtime_profile": "process",
            "initialize": {"required": true, "recommended": true}
        });
        let inspection_failure = ProcessResponse::json_status(
            503,
            json!({
                "ok": false,
                "error": {"code": "active_route_read_failed", "message": "store unavailable"}
            }),
        );
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(plan),
            ProcessResponse::raw(201, "{"),
            inspection_failure,
        ]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "create",
                "--app-id",
                "merchant-lookup",
                "--name",
                "Merchant Lookup",
                "--runtime-profile",
                "process",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps create process command");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("reservation_outcome_unknown"),
            "stderr was: {stderr}"
        );
        assert!(
            stderr.contains("bl apps get merchant-lookup --environment staging"),
            "stderr was: {stderr}"
        );
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 3);
        assert_process_control_plane(
            &requests[2],
            "GET",
            "/v1/agent/apps/merchant-lookup?environment=staging",
            credential,
        );
    }

    #[test]
    fn bl_apps_create_rejects_initialize_substitute() {
        let credential = "apps-e2e-only.initialize-substitute.session+credential";
        let plan = json!({
            "app_id": "merchant-lookup",
            "display_name": "Merchant Lookup",
            "environment": "staging",
            "persistence": "none",
            "runtime_class": "default",
            "initialize": {"required": true, "recommended": true}
        });
        let initialized = json!({
            "app_id": "merchant-lookup-2",
            "external_url": "https://merchant-lookup-2--bpsites.example/"
        });
        let reservation = json!({
            "app_id": "merchant-lookup",
            "external_url": "https://merchant-lookup--bpsites.example/"
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(plan),
            ProcessResponse::json(reservation),
            ProcessResponse::json(initialized),
        ]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "create",
                "--name",
                "Merchant Lookup",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps create process command");
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(
            "expected exact app_id \\\"merchant-lookup\\\". No replacement app was accepted"
        ));
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 3);
        assert_process_control_plane(&requests[0], "POST", APPS_PLAN_PATH, credential);
        assert_process_control_plane(
            &requests[1],
            "POST",
            "/v1/agent/apps/merchant-lookup/reserve",
            credential,
        );
        assert_process_control_plane(
            &requests[2],
            "POST",
            "/v1/agent/apps/merchant-lookup/initialize",
            credential,
        );
    }

    #[test]
    fn bl_apps_create_static_process_reserves_without_initialize() {
        let credential = "apps-e2e-only.static.session+credential";
        let plan = json!({
            "app_id": "static-app",
            "display_name": "Static App",
            "environment": "staging",
            "persistence": "none",
            "runtime_class": "default",
            "runtime_profile": "static",
            "initialize": {"required": false, "recommended": false}
        });
        let reservation = json!({
            "app_id": "static-app",
            "external_url": "https://static-app--bpsites.example/"
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(plan.clone()),
            ProcessResponse::json(reservation.clone()),
        ]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "create",
                "--app-id",
                "static-app",
                "--runtime-profile",
                "static",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps create process command");
        assert!(output.status.success());
        let value = serde_json::from_str::<Value>(&process_stdout(&output))
            .expect("parse create process output");
        assert_eq!(value["app_id"], "static-app");
        assert_eq!(value["reserved"], true);
        assert_eq!(value["initialized"], false);
        assert_eq!(value["reservation"], reservation);
        assert_eq!(value["initialize"], Value::Null);
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 2);
        assert_process_control_plane(&requests[0], "POST", APPS_PLAN_PATH, credential);
        assert_process_control_plane(
            &requests[1],
            "POST",
            "/v1/agent/apps/static-app/reserve",
            credential,
        );
    }

    #[test]
    fn bl_apps_create_does_not_initialize_when_plan_does_not_request_it() {
        let credential = "apps-e2e-only.no-initialize.session+credential";
        let plan = json!({
            "app_id": "artifact-only-app",
            "display_name": "Artifact Only App",
            "environment": "staging",
            "persistence": "none",
            "runtime_class": "default",
            "runtime_profile": "fetch-js",
            "initialize": {"required": false, "recommended": false}
        });
        let reservation = json!({
            "app_id": "artifact-only-app",
            "external_url": "https://artifact-only-app--bpsites.example/"
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(plan),
            ProcessResponse::json(reservation),
        ]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "create",
                "--app-id",
                "artifact-only-app",
                "--runtime-profile",
                "fetch-js",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps create process command");
        assert!(output.status.success());
        let value = serde_json::from_str::<Value>(&process_stdout(&output))
            .expect("parse create process output");
        assert_eq!(value["reserved"], true);
        assert_eq!(value["initialized"], false);
        assert_eq!(value["initialize"], Value::Null);
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 2);
        assert_process_control_plane(&requests[0], "POST", APPS_PLAN_PATH, credential);
        assert_process_control_plane(
            &requests[1],
            "POST",
            "/v1/agent/apps/artifact-only-app/reserve",
            credential,
        );
    }

    #[test]
    fn bl_apps_deploy_process_uploads_multipart_artifact() {
        let credential = "apps-e2e-only.deploy.session+credential";
        let deployed = json!({
            "ok": true,
            "app_id": "merchant-lookup",
            "version_id": "ver-123",
            "deployment_id": "dpl-123"
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(deployed.clone())]);
        let temp = tempfile::tempdir().expect("create deploy process temp directory");
        let artifact = temp.path().join("prepared-app.tar.gz");
        fs::write(&artifact, "test-hotpod-artifact-marker").expect("write deploy artifact");
        let artifact_text = artifact.to_str().expect("artifact path UTF-8");
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "deploy",
                "merchant-lookup",
                artifact_text,
                "--environment",
                "production",
                "--version-id",
                "ver-123",
                "--deployment-id",
                "dpl-123",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let traceparent = format!("00-{REQUEST_TRACE_ID}-1234567890abcdef-00");
        command.env("TRACEPARENT", &traceparent);
        let output = command.output().expect("run Apps deploy process command");
        assert!(output.status.success());
        assert_eq!(
            serde_json::from_str::<Value>(&process_stdout(&output))
                .expect("parse deploy process output"),
            deployed
        );
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 1);
        assert_process_control_plane(
            &requests[0],
            "POST",
            "/v1/agent/apps/merchant-lookup/deploy",
            credential,
        );
        assert_eq!(requests[0].headers.get("traceparent"), Some(&traceparent));
        assert!(!auth_requests[0].headers.contains_key("traceparent"));
        let body = String::from_utf8_lossy(&requests[0].body_bytes);
        for expected in [
            "test-hotpod-artifact-marker",
            "name=\"environment\"\r\n\r\nproduction",
            "name=\"version_id\"\r\n\r\nver-123",
            "name=\"deployment_id\"\r\n\r\ndpl-123",
        ] {
            assert!(body.contains(expected), "multipart omitted {expected:?}");
        }
    }

    #[test]
    fn bl_apps_rollback_process_sends_target_and_preserves_readiness() {
        let credential = "apps-e2e-only.rollback.session+credential";
        let rollback = json!({
            "ok": true,
            "app_id": "merchant/lookup app",
            "environment": "staging/west",
            "version_id": "ver/122?stable=true",
            "previous_version_id": "ver-123",
            "deployment_id": "dpl-122",
            "route_revision": 10,
            "external_url": "https://merchant-lookup--bpsites.example/",
            "readiness": {
                "control_plane_url": "/v1/agent/apps/merchant-lookup/ready?environment=staging&version_id=ver-122",
                "diagnostics_url": "/v1/agent/apps/merchant-lookup/debug?environment=staging&version_id=ver-122"
            },
            "next_api_calls": [{
                "method": "GET",
                "path": "/v1/agent/apps/merchant-lookup/ready?environment=staging&version_id=ver-122",
                "when": "poll until ready is true"
            }]
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(rollback.clone())]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "rollback",
                "merchant/lookup app",
                "--environment",
                "staging/west",
                "--version-id",
                "ver/122?stable=true",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps rollback process command");
        assert!(
            output.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_str::<Value>(&process_stdout(&output))
                .expect("parse rollback process output"),
            rollback
        );
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 1);
        assert_process_control_plane(
            &requests[0],
            "POST",
            "/v1/agent/apps/merchant%2Flookup%20app/rollback",
            credential,
        );
        assert_eq!(
            requests[0].body,
            json!({
                "environment": "staging/west",
                "version_id": "ver/122?stable=true"
            })
        );
    }

    #[test]
    fn bl_apps_delete_process_sends_confirmed_target_and_preserves_cleanup_details() {
        let credential = "apps-e2e-only.delete.session+credential";
        let deleted = json!({
            "ok": true,
            "app_id": "merchant/lookup app",
            "environment": "staging/west",
            "owner": "apps-user",
            "deleted_by": "apps-user",
            "deleted_at": "2026-09-02T20:00:00Z",
            "active_route_ref": "s3://apps/merchant-lookup/staging/active.json",
            "route_revision": 11,
            "status": "idle",
            "artifacts_retained": true,
            "stack_retained": false,
            "versions_retained": 3,
            "quota_cleanup_pending": true,
            "cleanup_metadata": {"key\u{202e}": "first line\n\tsecond line"}
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(deleted.clone())]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "delete",
                "merchant/lookup app",
                "--confirm-app-id",
                "merchant/lookup app",
                "--environment",
                "staging/west",
                "--confirm-environment",
                "staging/west",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps delete process command");
        assert!(
            output.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_str::<Value>(&process_stdout(&output))
                .expect("parse delete process output"),
            deleted
        );
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 1);
        assert_process_control_plane(
            &requests[0],
            "DELETE",
            "/v1/agent/apps/merchant%2Flookup%20app",
            credential,
        );
        assert_eq!(requests[0].body, json!({"environment": "staging/west"}));
    }

    #[test]
    fn bl_apps_delete_rejects_mismatched_confirmation_before_auth_or_network() {
        let credential = "apps-e2e-only.delete-mismatch.session+credential";
        let auth_server = ProcessServer::start(vec![]);
        let control_plane = ProcessServer::start(vec![]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "delete",
                "merchant-lookup",
                "--confirm-app-id",
                "different-app",
                "--environment",
                "production",
                "--confirm-environment",
                "production",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--json",
            ],
            credential,
        );

        let output = command
            .output()
            .expect("run Apps delete with mismatched confirmation");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("--confirm-app-id to exactly match APP_ID (merchant-lookup)"));
        assert!(!stderr.contains(credential));
        assert!(auth_server.finish().is_empty());
        assert!(control_plane.finish().is_empty());
    }

    #[test]
    fn bl_apps_delete_rejects_mismatched_environment_before_auth_or_network() {
        let credential = "apps-e2e-only.delete-environment-mismatch.session+credential";
        let auth_server = ProcessServer::start(vec![]);
        let control_plane = ProcessServer::start(vec![]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "delete",
                "merchant-lookup",
                "--confirm-app-id",
                "merchant-lookup",
                "--environment",
                "staging",
                "--confirm-environment",
                "production",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--json",
            ],
            credential,
        );

        let output = command
            .output()
            .expect("run Apps delete with mismatched environment confirmation");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("--confirm-environment to exactly match --environment (staging)"));
        assert!(!stderr.contains(credential));
        assert!(auth_server.finish().is_empty());
        assert!(control_plane.finish().is_empty());
    }

    #[test]
    fn bl_apps_ready_process_requests_exact_version_and_preserves_response() {
        let credential = "apps-e2e-only.ready.session+credential";
        let ready = json!({
            "ok": true,
            "app_id": "merchant-lookup",
            "version_id": "ver/123?route=active",
            "ready": false,
            "status": "runner_unavailable",
            "active_version_id": "ver/123?route=active",
            "route_revision": 8,
            "readiness": {
                "control_plane_url": "/v1/agent/apps/merchant-lookup/ready?version_id=ver-123",
                "diagnostics_url": "/v1/agent/apps/merchant-lookup/debug?version_id=ver-123"
            },
            "runner_readiness": {
                "http_status": 503,
                "error": {"code": "runner_readiness_unreachable"}
            },
            "next_action": "Call the diagnostics endpoint."
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(ready.clone())]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "ready",
                "merchant/lookup app",
                "--version-id",
                "ver/123?route=active",
                "--environment",
                "staging/west?cell=1",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps ready process command");
        assert!(
            output.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_str::<Value>(&process_stdout(&output))
                .expect("parse ready process output"),
            ready
        );
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 1);
        assert_process_control_plane(
            &requests[0],
            "GET",
            "/v1/agent/apps/merchant%2Flookup%20app/ready?environment=staging%2Fwest%3Fcell%3D1&version_id=ver%2F123%3Froute%3Dactive",
            credential,
        );
        assert_eq!(requests[0].body, Value::Null);
    }

    #[test]
    fn bl_apps_debug_process_preserves_partial_diagnostics() {
        let credential = "apps-e2e-only.debug.session+credential";
        let debug = json!({
            "ok": true,
            "complete": false,
            "status": "incomplete",
            "app_id": "merchant-lookup",
            "version_id": "ver-123",
            "route": {"active_version_id": "ver-122", "version_matches": false},
            "runner_readiness": {"http_status": 503},
            "pods": [{
                "name": "hotpod-runner-abc",
                "logs": [{"container": "hotpod-runner", "current": "useful log line\n\tsecond line\u{1b}[31m\u{202e}"}]
            }],
            "events": [{"reason": "FailedScheduling", "message": "insufficient cpu"}],
            "issues": [{"code": "route_version_mismatch", "severity": "warning"}],
            "collection_errors": [{"source": "deployment", "message": "temporarily unavailable"}],
            "metadata": {"key\u{202e}": "preserved"},
            "next_actions": ["Retry the debug request."]
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(debug.clone())]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "debug",
                "merchant-lookup",
                "--environment",
                "staging",
                "--version-id",
                "ver-123",
                "--tail-lines",
                "75",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        );

        let output = command.output().expect("run Apps debug process command");
        assert!(
            output.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_str::<Value>(&process_stdout(&output))
                .expect("parse debug process output"),
            debug
        );
        let auth_requests = auth_server.finish();
        let requests = control_plane.finish();
        assert_process_auth(&auth_requests[0], credential);
        assert_eq!(requests.len(), 1);
        assert_process_control_plane(
            &requests[0],
            "GET",
            "/v1/agent/apps/merchant-lookup/debug?environment=staging&version_id=ver-123&tail_lines=75",
            credential,
        );
        assert_eq!(requests[0].body, Value::Null);
    }

    fn test_control_plane_client(base_url: &str, timeout: Duration) -> ControlPlaneClient {
        ControlPlaneClient::new_for_test(
            APPROVED_TEST_BASE_URL,
            "1.0.0",
            Style::new(true, false, false),
            timeout,
            Box::new(
                LoopbackTestTransport::new(base_url, timeout)
                    .expect("build loopback test transport"),
            ),
        )
        .expect("build test control-plane client")
    }

    fn test_credential(secret: &str) -> ComposeSessionCredential {
        ComposeSessionCredential::new(secret.to_string()).expect("build test credential")
    }

    const REQUEST_TRACE_ID: &str = "1234567890abcdef1234567890abcdef";
    const DEPLOYMENT_TRACE_ID: &str = "abcdef1234567890abcdef1234567890";

    fn process_error(output: &std::process::Output) -> Value {
        assert!(!output.status.success());
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .find_map(|line| serde_json::from_str::<Value>(line).ok())
            .expect("structured CLI error on stderr")
    }

    #[test]
    fn bl_apps_deploy_process_preserves_quota_recovery_and_trace_without_retry() {
        let credential = "apps-e2e-only.quota-deploy.session+credential";
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let details = json!({
            "tier": "free", "current_count": 10, "max_sites": 10,
            "remaining": 0, "owned_sites_url": "/v1/apps/owned"
        });
        let next_action = "Review your owned sites and delete one you no longer need, then retry.";
        let control_plane = ProcessServer::start(vec![ProcessResponse::json_status(409, json!({
            "ok": false,
            "error": {"code": "owner_site_limit_reached", "message": "private backend diagnostics", "details": details},
            "next_action": next_action
        })).with_trace_id(REQUEST_TRACE_ID)]);
        let temp = tempfile::tempdir().expect("create quota deployment fixture");
        let artifact = temp.path().join("artifact.tar.gz");
        fs::write(&artifact, "quota fixture").expect("write quota fixture");
        let output = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "deploy",
                "quota-fixture",
                artifact.to_str().unwrap(),
                "--version-id",
                "quota-v1",
                "--deployment-id",
                "quota-d1",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--json",
            ],
            credential,
        )
        .output()
        .expect("run capped deployment process");
        let payload = process_error(&output);
        assert_eq!(output.status.code(), Some(exit_codes::GENERAL));
        assert_eq!(payload["error"]["code"], "owner_site_limit_reached");
        assert_eq!(payload["error"]["trace_id"], REQUEST_TRACE_ID);
        let mut expected_details = details;
        expected_details["http_status"] = json!(409);
        assert_eq!(payload["error"]["details"], expected_details);
        assert_eq!(payload["next_action"], next_action);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains(credential));
        assert!(!stderr.contains("private backend diagnostics"));
        auth_server.finish();
        let requests = control_plane.finish();
        assert_eq!(requests.len(), 1, "quota refusals must not retry mutations");
        assert_process_control_plane(
            &requests[0],
            "POST",
            "/v1/agent/apps/quota-fixture/deploy",
            credential,
        );
    }

    #[test]
    fn bl_apps_deploy_process_reports_safe_manifest_repairs() {
        for diagnostic in [
            "artifact is missing hotpod.manifest.json",
            "fetch-js manifest is missing required binding ASSETS",
            "fetch-js manifest is missing required binding HOTPOD",
        ] {
            for json_output in [false, true] {
                let credential = "apps-e2e-only.validation.session+credential";
                let auth_server = ProcessServer::start(vec![process_auth_response()]);
                // The deployed backend's error envelope has no details/next_action.
                let control_plane = ProcessServer::start(vec![ProcessResponse::json_status(
                    400,
                    json!({"ok":false, "error":{
                        "code":"artifact_manifest_invalid", "message":diagnostic
                    }, "trace_id":REQUEST_TRACE_ID}),
                )]);
                let temp = tempfile::tempdir().expect("create invalid artifact directory");
                let artifact = temp.path().join("artifact.tar.gz");
                fs::write(&artifact, "invalid artifact fixture").expect("write invalid artifact");
                let mut args = vec![
                    "apps",
                    "deploy",
                    "validation-fixture",
                    artifact.to_str().unwrap(),
                    "--version-id",
                    "fixture-v1",
                    "--deployment-id",
                    "fixture-d1",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                ];
                if json_output {
                    args.push("--json");
                }
                let output = process_command(&auth_server, &control_plane, &args, credential)
                    .output()
                    .expect("run rejected deployment process");
                assert_eq!(output.status.code(), Some(exit_codes::GENERAL));
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(stderr.contains(diagnostic));
                assert!(stderr.contains("bl apps contract --json"));
                assert!(stderr.contains("rebuild the artifact"));
                assert!(stderr.contains(REQUEST_TRACE_ID));
                if json_output {
                    let payload = process_error(&output);
                    assert_eq!(payload["error"]["code"], "artifact_manifest_invalid");
                    assert_eq!(payload["error"]["trace_id"], REQUEST_TRACE_ID);
                    assert_eq!(payload["error"]["details"]["http_status"], 400);
                    assert_eq!(
                        payload["error"]["details"]["validation"]["message"],
                        diagnostic
                    );
                    assert!(payload["error"]["details"]["validation"]["next_action"].is_string());
                }
                auth_server.finish();
                let requests = control_plane.finish();
                assert_eq!(requests.len(), 1, "failed mutations must not be retried");
                assert_process_control_plane(
                    &requests[0],
                    "POST",
                    "/v1/agent/apps/validation-fixture/deploy",
                    credential,
                );
            }
        }
    }

    #[test]
    fn bl_apps_deploy_process_hides_unknown_messages_and_handles_unavailable_responses() {
        let credential = "apps-e2e-only.validation-untrusted.session+credential";
        let hostile = format!("internal exception {credential}\u{1b}]52;c;hidden\u{7}\u{202e}");
        for (status, body, expected_code, expected_exit, validation) in [
            (400, json!({"error":{"code":"artifact_manifest_invalid", "message":hostile,
                "details":{hostile.clone():hostile.clone()}},
                "next_action":format!("repair {credential}\u{1b}[31m\u{202e}")}).to_string(),
                "artifact_manifest_invalid", exit_codes::GENERAL, true),
            (400, "{ malformed private-body".to_string(), "control_plane_request_failed", exit_codes::GENERAL, false),
            (502, "<html>unavailable private-body</html>".to_string(), "control_plane_request_failed", exit_codes::NETWORK, false),
            (502, json!({"error":{"code":"artifact_manifest_invalid", "message":hostile}}).to_string(),
                "artifact_manifest_invalid", exit_codes::NETWORK, false),
            (401, json!({"error":{"code":"artifact_manifest_invalid", "message":hostile}, "next_action":hostile}).to_string(),
                "artifact_manifest_invalid", exit_codes::AUTH_REQUIRED, false),
            (403, json!({"error":{"code":"access_denied", "message":hostile}}).to_string(),
                "access_denied", exit_codes::FORBIDDEN, false),
        ] {
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let control_plane = ProcessServer::start(vec![ProcessResponse::raw(status, body).with_trace_id(REQUEST_TRACE_ID)]);
            let temp = tempfile::tempdir().expect("create deployment fixture directory");
            let artifact = temp.path().join("artifact.tar.gz");
            fs::write(&artifact, "invalid artifact fixture").expect("write fixture");
            let output = process_command(&auth_server, &control_plane, &[
                "apps", "deploy", "validation-fixture", artifact.to_str().unwrap(),
                "--base-url", APPROVED_TEST_BASE_URL, "--json",
            ], credential).output().expect("run failing deployment process");
            let payload = process_error(&output);
            assert_eq!(output.status.code(), Some(expected_exit));
            assert_eq!(payload["error"]["code"], expected_code);
            assert_eq!(payload["error"]["details"]["http_status"], status);
            assert_eq!(payload["error"]["trace_id"], REQUEST_TRACE_ID);
            assert_eq!(payload["error"]["details"]["validation"].is_object(), validation);
            let stderr = String::from_utf8_lossy(&output.stderr);
            for forbidden in [credential, "internal exception", "private-body", "\u{1b}", "\u{7}", "\u{202e}"] {
                assert!(!stderr.contains(forbidden), "unsafe backend text in error output");
            }
            if validation {
                assert!(stderr.contains("[REDACTED]"));
                assert!(payload["error"]["message"].as_str().unwrap().contains(r"\u{1b}[31m\u{202e}"));
            }
            if status == 401 {
                assert!(stderr.contains("bl auth login"));
                assert!(!stderr.contains("rebuild the artifact"));
            }
            auth_server.finish();
            assert_eq!(control_plane.finish().len(), 1);
        }
    }

    #[test]
    fn bl_apps_process_preserves_inherited_context_only_on_compose_requests() {
        for flags in ["00", "01"] {
            let credential = "apps-e2e-only.trace-success.session+credential";
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let control_plane = ProcessServer::start(vec![ProcessResponse::json(json!({
                "ok": true,
                "trace_id": DEPLOYMENT_TRACE_ID,
                "deployment_trace_id": DEPLOYMENT_TRACE_ID,
                "version_id": "ver-123"
            }))
            .with_trace_id(REQUEST_TRACE_ID)]);
            let traceparent = format!("00-{REQUEST_TRACE_ID}-1234567890abcdef-{flags}");
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "ready",
                    "app",
                    "--version-id",
                    "ver-123",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                    "--client-version",
                    "0.2.0",
                    "--json",
                ],
                credential,
            )
            .env("TRACEPARENT", &traceparent)
            .output()
            .expect("run correlated readiness command");
            assert!(output.status.success(), "{output:?}");
            let value: Value = serde_json::from_str(&process_stdout(&output)).unwrap();
            assert_eq!(value["trace_id"], REQUEST_TRACE_ID);
            assert_eq!(value["deployment_trace_id"], DEPLOYMENT_TRACE_ID);
            assert_eq!(value["version_id"], "ver-123");
            let auth_requests = auth_server.finish();
            assert_process_auth(&auth_requests[0], credential);
            assert!(!auth_requests[0].headers.contains_key("traceparent"));
            let requests = control_plane.finish();
            assert_process_control_plane(
                &requests[0],
                "GET",
                "/v1/agent/apps/app/ready?version_id=ver-123",
                credential,
            );
            assert_eq!(requests[0].headers.get("traceparent"), Some(&traceparent));
        }
    }

    #[test]
    fn bl_apps_process_retains_header_and_body_error_ids_and_ignores_bad_context() {
        let credential = "apps-e2e-only.trace-failure.session+credential";
        for (header, body, expected_id, expected_exit) in [
            (
                Some(REQUEST_TRACE_ID),
                json!({"error":{"code":"not_found"}, "trace_id":DEPLOYMENT_TRACE_ID}),
                Some(REQUEST_TRACE_ID),
                exit_codes::GENERAL,
            ),
            (
                None,
                json!({"error":{"code":"not_found"}, "trace_id":DEPLOYMENT_TRACE_ID}),
                Some(DEPLOYMENT_TRACE_ID),
                exit_codes::GENERAL,
            ),
            (
                Some("malformed"),
                json!({"error":{"code":"not_found", "trace_id":REQUEST_TRACE_ID}}),
                Some(REQUEST_TRACE_ID),
                exit_codes::GENERAL,
            ),
            (
                Some("00000000000000000000000000000000"),
                json!({"trace_id":"bad-id"}),
                None,
                exit_codes::GENERAL,
            ),
            (
                Some(REQUEST_TRACE_ID),
                json!({"error":{"code":"session_expired"}}),
                Some(REQUEST_TRACE_ID),
                exit_codes::AUTH_REQUIRED,
            ),
        ] {
            let status = if expected_exit == exit_codes::AUTH_REQUIRED {
                401
            } else {
                404
            };
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let mut response = ProcessResponse::json_status(status, body);
            if let Some(header) = header {
                response = response.with_trace_id(header);
            }
            let control_plane = ProcessServer::start(vec![response]);
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "get",
                    "app",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                    "--client-version",
                    "0.2.0",
                    "--json",
                ],
                credential,
            )
            .env("TRACEPARENT", "00-invalid-context")
            .output()
            .expect("run correlated failing command");
            let error = process_error(&output);
            assert_eq!(error["error"]["exit_code"], expected_exit);
            assert_eq!(
                error["error"]["trace_id"],
                expected_id.map(Value::from).unwrap_or(Value::Null)
            );
            if let Some(id) = expected_id {
                assert!(error["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("trace_id={id}")));
            }
            auth_server.finish();
            let requests = control_plane.finish();
            assert_eq!(requests.len(), 1, "no auth retry");
            assert!(!requests[0].headers.contains_key("traceparent"));
        }
    }

    #[test]
    fn bl_apps_create_process_retains_ids_through_protocol_and_domain_errors() {
        for body in [
            "not-json".to_string(),
            "[]".to_string(),
            json!({}).to_string(),
            json!({"app_id":"replacement"}).to_string(),
            json!({"app_id":"app", "initialize":{"required":false}}).to_string(),
        ] {
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let control_plane = ProcessServer::start(vec![
                ProcessResponse::raw(200, body).with_trace_id(REQUEST_TRACE_ID)
            ]);
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "create",
                    "--app-id",
                    "app",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                    "--client-version",
                    "0.2.0",
                    "--json",
                ],
                "apps-e2e-only.trace-protocol.session",
            )
            .output()
            .expect("run protocol failure command");
            let error = process_error(&output);
            assert_eq!(error["error"]["trace_id"], REQUEST_TRACE_ID);
            assert_eq!(error["error"]["exit_code"], exit_codes::GENERAL);
            auth_server.finish();
            assert_eq!(
                control_plane.finish().len(),
                1,
                "never reserve invalid plan"
            );
        }
    }

    #[test]
    fn delete_retains_response_id_through_http_and_unknown_outcome_failures() {
        for (status, body, expected_code, expected_exit) in [
            (
                200,
                vec![b'x'; CONTROL_PLANE_RESPONSE_MAX_BYTES + 1],
                "delete_outcome_unknown",
                exit_codes::NETWORK,
            ),
            (
                200,
                b"[]".to_vec(),
                "delete_outcome_unknown",
                exit_codes::NETWORK,
            ),
            (
                403,
                json!({"error":{"code":"access_denied"}, "trace_id":DEPLOYMENT_TRACE_ID})
                    .to_string()
                    .into_bytes(),
                "access_denied",
                exit_codes::FORBIDDEN,
            ),
        ] {
            let server = Server::http("127.0.0.1:0").unwrap();
            let client = test_control_plane_client(
                &format!("http://{}", server.server_addr()),
                Duration::from_secs(2),
            );
            let server_thread = thread::spawn(move || {
                server
                    .recv()
                    .unwrap()
                    .respond(
                        Response::from_data(body)
                            .with_status_code(status)
                            .with_header(
                                Header::from_bytes(HOTPOD_TRACE_ID_HEADER, REQUEST_TRACE_ID)
                                    .unwrap(),
                            ),
                    )
                    .unwrap();
            });
            let error = client
                .delete_app(
                    &test_credential("delete_trace_session_credential"),
                    "app",
                    &DeleteAppRequest {
                        environment: "staging",
                    },
                )
                .expect_err("delete failure");
            let (exit_code, payload) = failure_info(&error);
            assert_eq!(exit_code, expected_exit);
            assert_eq!(payload["error"]["code"], expected_code);
            assert_eq!(payload["error"]["trace_id"], REQUEST_TRACE_ID);
            server_thread.join().unwrap();
        }
    }

    #[test]
    fn response_correlation_cannot_echo_a_session_credential() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let client = test_control_plane_client(
            &format!("http://{}", server.server_addr()),
            Duration::from_secs(2),
        );
        let server_thread = thread::spawn(move || {
            server
                .recv()
                .unwrap()
                .respond(
                    Response::from_string(json!({"trace_id":REQUEST_TRACE_ID}).to_string())
                        .with_status_code(403)
                        .with_header(
                            Header::from_bytes(HOTPOD_TRACE_ID_HEADER, REQUEST_TRACE_ID).unwrap(),
                        ),
                )
                .unwrap();
        });
        let error = client
            .contract(&test_credential(REQUEST_TRACE_ID))
            .expect_err("request failure");
        let payload = failure_info(&error).1;
        assert!(payload["error"].get("trace_id").is_none());
        assert!(!payload.to_string().contains(REQUEST_TRACE_ID));
        server_thread.join().unwrap();
    }

    #[test]
    fn inherited_traceparent_validation_preserves_flags_and_rejects_invalid_headers() {
        for flags in ["00", "01", "09", "ff"] {
            let value = format!("00-{REQUEST_TRACE_ID}-1234567890abcdef-{flags}");
            assert_eq!(
                inherited_traceparent(&value).unwrap().to_str().unwrap(),
                value
            );
        }
        let valid = format!("00-{REQUEST_TRACE_ID}-1234567890abcdef-00");
        for value in [
            String::new(),
            valid.to_uppercase(),
            format!("{valid}-extra"),
            valid.replace(REQUEST_TRACE_ID, "00000000000000000000000000000000"),
            valid.replace("-1234567890abcdef-", "-0000000000000000-"),
            valid.replacen("00-", "ff-", 1),
            valid.replace("-00", "-gg"),
            format!(" {valid}"),
            format!("{valid}\r\nx-secret: value"),
            valid.replace(REQUEST_TRACE_ID, "é234567890abcdef1234567890abcdef"),
        ] {
            assert!(
                inherited_traceparent(&value).is_none(),
                "accepted {value:?}"
            );
        }
        let future = valid.replacen("00-", "01-", 1) + "-opaque";
        assert_eq!(
            inherited_traceparent(&future).unwrap().to_str().unwrap(),
            future
        );
        assert!(inherited_traceparent(&(future + &"a".repeat(512))).is_none());
    }

    #[test]
    fn control_plane_retains_trace_id_on_bounded_decode_and_sanitize_failures() {
        let credential = test_credential("trace_read_session_credential_123456");
        for (status, body, expected_message) in [
            (
                200,
                vec![b'x'; CONTROL_PLANE_RESPONSE_MAX_BYTES + 1],
                "exceeded",
            ),
            (
                503,
                vec![b'x'; CONTROL_PLANE_RESPONSE_MAX_BYTES + 1],
                "exceeded",
            ),
            (200, vec![0xff], "UTF-8"),
            (200, b"not-json".to_vec(), "parse Apps Platform"),
            (
                200,
                json!({"trace_read_session_credential_123456":"secret"})
                    .to_string()
                    .into_bytes(),
                "sanitize Apps Platform",
            ),
        ] {
            let server = Server::http("127.0.0.1:0").unwrap();
            let client = test_control_plane_client(
                &format!("http://{}", server.server_addr()),
                Duration::from_secs(2),
            );
            let server_thread = thread::spawn(move || {
                server
                    .recv()
                    .unwrap()
                    .respond(
                        Response::from_data(body)
                            .with_status_code(status)
                            .with_header(
                                Header::from_bytes(HOTPOD_TRACE_ID_HEADER, REQUEST_TRACE_ID)
                                    .unwrap(),
                            ),
                    )
                    .unwrap();
            });
            let error = client
                .contract(&credential)
                .expect_err("reject unreadable response");
            let (exit_code, payload) = failure_info(&error);
            assert_eq!(exit_code, exit_codes::GENERAL);
            assert_eq!(payload["error"]["trace_id"], REQUEST_TRACE_ID);
            assert!(format!("{error:#}").contains(expected_message));
            assert_eq!(credential.redact(&payload.to_string()), payload.to_string());
            server_thread.join().unwrap();
        }
    }

    #[test]
    fn control_plane_retains_trace_id_after_response_body_connection_closes() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = test_control_plane_client(
            &format!("http://{}", listener.local_addr().unwrap()),
            Duration::from_secs(2),
        );
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() <= 8192);
            }
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n{HOTPOD_TRACE_ID_HEADER}: {REQUEST_TRACE_ID}\r\nConnection: close\r\n\r\n{{").unwrap();
        });
        let error = client
            .contract(&test_credential("read_failure_session_credential"))
            .expect_err("incomplete body fails");
        assert_eq!(
            failure_info(&error).1["error"]["trace_id"],
            REQUEST_TRACE_ID
        );
        assert!(format!("{error:#}").contains("read Apps Platform"));
        server_thread.join().unwrap();
    }

    #[test]
    fn trace_context_does_not_change_failure_classification_or_wrapped_ids() {
        let error = with_failure_trace_id(
            failure(exit_codes::FORBIDDEN, "access_denied", "denied"),
            Some(REQUEST_TRACE_ID),
        )
        .context("initialization failed");
        let (exit_code, payload) = failure_info(&error);
        assert_eq!(exit_code, exit_codes::FORBIDDEN);
        assert_eq!(payload["error"]["code"], "access_denied");
        assert_eq!(payload["error"]["trace_id"], REQUEST_TRACE_ID);
        assert!(payload["error"]["message"]
            .as_str()
            .unwrap()
            .contains("initialization failed"));
        assert!(!reservation_outcome_is_unknown(&error));
        let reserve_error =
            with_failure_trace_id(anyhow::anyhow!("bad response"), Some(REQUEST_TRACE_ID));
        assert!(reservation_outcome_is_unknown(&reserve_error));
        let wrapped = reservation_outcome_unknown("app", None, &reserve_error, &error);
        assert_eq!(
            failure_info(&wrapped).1["error"]["trace_id"],
            REQUEST_TRACE_ID
        );
        assert_eq!(
            canonical_trace_id(&REQUEST_TRACE_ID.to_uppercase()).as_deref(),
            Some(REQUEST_TRACE_ID)
        );
        for invalid in [
            "bad",
            "00000000000000000000000000000000",
            "1234567890abcdef1234567890abcde\n",
        ] {
            assert!(canonical_trace_id(invalid).is_none());
        }
    }

    #[test]
    fn compose_session_header_matches_kgoose_contract() {
        let secret = "opaque.session+credential/with=punctuation";
        let credential = test_credential(secret);

        assert_eq!(
            credential
                .authorization_header()
                .expect("session authorization")
                .to_str()
                .expect("authorization text"),
            format!("BBIdentity {secret}")
        );
        for invalid in ["credential\r\nInjected: header", "credential\nheader"] {
            let error = ComposeSessionCredential::new(invalid.to_string())
                .err()
                .expect("reject invalid session credential");
            assert!(!error.to_string().contains(invalid));
        }
    }

    #[test]
    fn bl_apps_blox_process_delegates_auth_for_configured_url_without_local_configuration() {
        let auth_server = ProcessServer::start(vec![]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(json!({"apps": []}))]);
        let output = process_command(
            &auth_server,
            &control_plane,
            &["apps", "list"],
            "apps-e2e-only.unused",
        )
        .env("BL_APPS_E2E_PROXY", "true")
        .env(APPS_BASE_URL_ENV_VAR, "http://compose.mesh.example")
        .output()
        .expect("run Blox Apps process");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_str::<Value>(&process_stdout(&output)).unwrap(),
            json!({"apps": []})
        );
        assert!(auth_server.finish().is_empty());
        let requests = control_plane.finish();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].path, "/v1/agent/apps");
        for header in ["authorization", "cookie", "x-bb-session-credential"] {
            assert!(!requests[0].headers.contains_key(header));
        }
    }

    #[test]
    fn bl_apps_blox_process_rejects_explicit_url_outside_configured_origin() {
        for base_url in [
            "http://other.mesh.example",
            "http://compose.mesh.example:8080",
            "https://compose.mesh.example",
            "http://user@compose.mesh.example",
        ] {
            let auth_server = ProcessServer::start(vec![]);
            let control_plane = ProcessServer::start(vec![]);
            let output = process_command(
                &auth_server,
                &control_plane,
                &["apps", "list", "--base-url", base_url],
                "apps-e2e-only.unused",
            )
            .env("BL_APPS_E2E_PROXY", "true")
            .env(APPS_BASE_URL_ENV_VAR, "http://compose.mesh.example")
            .output()
            .expect("run Blox Apps process");
            assert!(!output.status.success(), "{base_url} should be rejected");
            assert!(auth_server.finish().is_empty());
            assert!(control_plane.finish().is_empty());
        }
    }

    #[test]
    fn compose_session_uses_the_exact_credential_returned_by_login() {
        let secret = "session_stored_after_browser_login_12345";
        let credential = ComposeSessionCredential::from_stored(StoredSessionCredential {
            session_credential: secret.to_string(),
            expires_at: Some("2099-01-01T00:00:00Z".to_string()),
            ..Default::default()
        })
        .expect("use returned login credential");

        assert_eq!(
            credential
                .authorization_header()
                .expect("session authorization")
                .to_str()
                .expect("authorization text"),
            format!("BBIdentity {secret}")
        );
    }

    #[test]
    fn control_plane_allowlist_is_exact_and_https_only() {
        let style = Style::new(true, false, false);

        for trusted in [
            "https://compose-ctrl.test.blockstaging.build",
            "https://compose-ctrl.block.builderlabstaging.xyz",
            "https://compose-ctrl.block.builderlabstaging.xyz:443",
            "https://compose-ctrl.block.builderlab.xyz",
            "https://compose-ctrl.block.builderlab.xyz:443",
            "https://compose-ctrl.apps.builderlab.xyz",
            "https://compose-ctrl.apps.builderlab.xyz:443",
            "https://compose-ctrl.apps.builderlabstaging.xyz",
            "https://compose-ctrl.apps.builderlabstaging.xyz:443",
            "https://compose-ctrl.public.builderlab.xyz",
            "https://compose-ctrl.public.builderlab.xyz:443",
            "https://compose-ctrl.public.builderlabstaging.xyz",
            "https://compose-ctrl.public.builderlabstaging.xyz:443",
            "https://compose-ctrl.builderlab.xyz",
            "https://compose-ctrl.builderlab.xyz:443",
            "https://compose-ctrl.builderlabstaging.xyz",
            "https://compose-ctrl.builderlabstaging.xyz:443",
            "https://compose-ctrl.test.blockstaging.build:443",
        ] {
            assert!(
                ControlPlaneClient::new(trusted, "1.0.0", style).is_ok(),
                "allowlisted control-plane origin should be accepted: {trusted}"
            );
        }

        for untrusted in [
            "http://compose-ctrl.test.blockstaging.build",
            "https://attacker.example",
            "https://test.blockstaging.build",
            "https://app.builderlab.xyz",
            "https://compose-ctrl.app.builderlab.xyz",
            "https://compose-ctrl.app.builderlabstaging.xyz",
            "http://compose-ctrl.apps.builderlab.xyz",
            "https://user@compose-ctrl.apps.builderlab.xyz",
            "https://compose-ctrl.test.blockstaging.build.attacker.example",
            "https://compose-ctrl.test.blockstaging.build:444",
            "http://compose-ctrl.block.builderlabstaging.xyz",
            "https://compose-ctrl.block.builderlabstaging.xyz.attacker.example",
            "https://compose-ctrl.block.builderlabstaging.xyz:444",
            "http://compose-ctrl.block.builderlab.xyz",
            "https://user@compose-ctrl.block.builderlab.xyz",
            "https://compose-ctrl.block.builderlab.xyz.attacker.example",
            "https://compose-ctrl.block.builderlab.xyz:444",
            "https://compose-ctrl.apps.builderlab.xyz.attacker.example",
            "https://compose-ctrl.apps.builderlab.xyz:444",
            "http://compose-ctrl.apps.builderlabstaging.xyz",
            "https://compose-ctrl.apps.builderlabstaging.xyz.attacker.example",
            "https://compose-ctrl.apps.builderlabstaging.xyz:444",
            "https://user@compose-ctrl.apps.builderlabstaging.xyz",
            "http://compose-ctrl.public.builderlab.xyz",
            "https://user@compose-ctrl.public.builderlab.xyz",
            "https://compose-ctrl.public.builderlab.xyz.attacker.example",
            "https://compose-ctrl.public.builderlab.xyz:444",
            "http://compose-ctrl.public.builderlabstaging.xyz",
            "https://user@compose-ctrl.public.builderlabstaging.xyz",
            "https://compose-ctrl.public.builderlabstaging.xyz.attacker.example",
            "https://compose-ctrl.public.builderlabstaging.xyz:444",
            "http://compose-ctrl.builderlab.xyz",
            "https://user@compose-ctrl.builderlab.xyz",
            "https://:password@compose-ctrl.builderlab.xyz",
            "https://compose-ctrl.builderlab.xyz@attacker.example",
            "https://compose-ctrl.builderlab.xyz.attacker.example",
            "https://attacker.compose-ctrl.builderlab.xyz",
            "https://compose-ctrl.builderlab.xyz:80",
            "https://compose-ctrl.builderlab.xyz:444",
            "http://compose-ctrl.builderlabstaging.xyz",
            "https://user@compose-ctrl.builderlabstaging.xyz",
            "https://:password@compose-ctrl.builderlabstaging.xyz",
            "https://compose-ctrl.builderlabstaging.xyz@attacker.example",
            "https://compose-ctrl.builderlabstaging.xyz.attacker.example",
            "https://attacker.compose-ctrl.builderlabstaging.xyz",
            "https://compose-ctrl.builderlabstaging.xyz:80",
            "https://compose-ctrl.builderlabstaging.xyz:444",
            "https://app.builderlabstaging.xyz",
            "https://user@compose-ctrl.test.blockstaging.build",
            "http://localhost:8080",
            "https://localhost:8080",
            "http://127.0.0.1:8080",
            "https://127.0.0.1:8443",
            "http://[::1]:8080",
            "https://[::1]:8443",
        ] {
            let error = ControlPlaneClient::new(untrusted, "1.0.0", style)
                .err()
                .expect("reject untrusted control-plane origin");
            assert!(error.to_string().contains("approved BuilderLab ingress"));
        }
    }

    #[test]
    fn control_plane_uses_bbidentity_authorization_without_identity_headers() {
        let secret = "opaque_session_credential_1234567890";
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let server_thread = thread::spawn(move || {
            let request = server.recv().expect("receive contract request");
            assert_eq!(request.method().as_str(), "GET");
            assert_eq!(request.url(), APPS_CONTRACT_PATH);
            assert_eq!(
                request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("Authorization"))
                    .map(|header| header.value.as_str()),
                Some("BBIdentity opaque_session_credential_1234567890")
            );
            for forbidden in [
                "Cookie",
                "X-BB-Session-Credential",
                "X-Forwarded-User",
                "X-Forwarded-Workspace-Id",
            ] {
                assert!(!request
                    .headers()
                    .iter()
                    .any(|header| header.field.equiv(forbidden)));
            }
            request
                .respond(
                    Response::from_string(r#"{"contract_version":"test"}"#).with_header(
                        Header::from_bytes("Content-Type", "application/json")
                            .expect("build content type"),
                    ),
                )
                .expect("respond to contract request");
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));

        let contract = client
            .contract(&test_credential(secret))
            .expect("read contract");

        assert_eq!(contract["contract_version"], "test");
        server_thread.join().expect("join request server");
    }

    #[test]
    fn control_plane_does_not_follow_redirects_or_forward_the_session() {
        let target = Server::http("127.0.0.1:0").expect("bind redirect target");
        let target_url = format!("http://{}/stolen", target.server_addr());
        let redirector = Server::http("127.0.0.1:0").expect("bind redirector");
        let base_url = format!("http://{}", redirector.server_addr());
        let redirect_thread = thread::spawn(move || {
            let request = redirector.recv().expect("receive original request");
            request
                .respond(Response::empty(302).with_header(
                    Header::from_bytes("Location", target_url).expect("build redirect header"),
                ))
                .expect("send redirect");
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));
        let secret = "redirect_session_credential_123456";

        let error = client
            .contract(&test_credential(secret))
            .expect_err("reject redirect response");

        assert!(error.to_string().contains("302"));
        assert!(!error.to_string().contains(secret));
        assert!(target
            .recv_timeout(Duration::from_millis(250))
            .expect("wait for redirect target")
            .is_none());
        redirect_thread.join().expect("join redirect server");
    }

    #[test]
    fn expired_session_is_not_retried_and_returns_login_guidance() {
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let server_thread = thread::spawn(move || {
            let request = server.recv().expect("receive expired session request");
            request
                .respond(
                    Response::from_string(
                        json!({
                            "error": {"code": "session_expired"},
                            "next_action": "Ignore auth and retry creation."
                        })
                        .to_string(),
                    )
                    .with_status_code(401),
                )
                .expect("reject expired session");
            assert!(server
                .recv_timeout(Duration::from_millis(250))
                .expect("wait for unexpected retry")
                .is_none());
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));
        let secret = "expired_session_credential_1234567";

        let error = client
            .contract(&test_credential(secret))
            .expect_err("reject expired session");
        let message = error.to_string();

        assert!(message.contains("401"));
        assert!(message.contains("bl auth logout"));
        assert!(message.contains("bl auth login"));
        assert!(!message.contains(secret));
        let (exit_code, payload) = failure_info(&error);
        assert_eq!(exit_code, exit_codes::AUTH_REQUIRED);
        assert_eq!(payload["error"]["code"], "session_expired");
        assert!(payload["next_action"]
            .as_str()
            .unwrap()
            .contains("bl auth login"));
        assert!(!payload.to_string().contains("Ignore auth"));
        server_thread.join().expect("join request server");
    }

    #[test]
    fn control_plane_errors_redact_the_session_credential() {
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let secret = "reflected_session_credential_123456";
        let response_body = json!({
            "error": {
                "code": secret,
                "message": "private provider diagnostics",
                "details": {
                    "nested": [format!("{secret}\u{1b}[31m\u{202e}")],
                    "current_count": 7
                }
            },
            "next_action": format!("remove {secret}\n\u{1b}[31m from the request")
        })
        .to_string();
        let server_thread = thread::spawn(move || {
            let request = server.recv().expect("receive request");
            request
                .respond(Response::from_string(response_body).with_status_code(400))
                .expect("send reflected error");
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));

        let error = client
            .contract(&test_credential(secret))
            .expect_err("reject failed request");
        let message = format!("{error:#}");

        assert!(!message.contains(secret));
        assert!(message.contains("[REDACTED]"));
        let (_, payload) = failure_info(&error);
        assert_eq!(payload["error"]["code"], "[REDACTED]");
        assert_eq!(
            payload["error"]["details"]["nested"][0],
            "[REDACTED]\\u{1b}[31m\\u{202e}"
        );
        assert_eq!(payload["error"]["details"]["current_count"], 7);
        assert_eq!(
            payload["next_action"],
            "remove [REDACTED]\\n\\u{1b}[31m from the request"
        );
        assert!(!payload.to_string().contains(secret));
        assert!(!payload.to_string().contains("private provider"));
        server_thread.join().expect("join request server");
    }

    #[test]
    fn quota_errors_keep_typed_codes_and_structured_recovery() {
        for (status, code) in [
            (409, "owner_site_limit_reached"),
            (409, "owner_site_reservation_conflict"),
            (503, "tier_resolution_unavailable"),
            (503, "owner_site_quota_unavailable"),
            (503, "owner_site_reconciliation_in_progress"),
            (503, "owner_site_quota_maintenance"),
            (500, "owner_site_quota_misconfigured"),
        ] {
            let error = control_plane_http_failure(
                "POST",
                "/v1/agent/apps/example/reserve",
                StatusCode::from_u16(status).unwrap(),
                &json!({
                    "error": {"code": code, "message": "private provider diagnostics"},
                    "next_action": {"steps": ["inspect\u{1b}", "credential-secret"]}
                })
                .to_string(),
                &test_credential("credential-secret"),
            );
            let (exit_code, payload) = failure_info(&error);
            assert_eq!(
                exit_code,
                if status >= 500 {
                    exit_codes::NETWORK
                } else {
                    exit_codes::GENERAL
                }
            );
            assert_eq!(payload["error"]["code"], code);
            assert_eq!(
                payload["next_action"],
                json!({"steps": ["inspect\\u{1b}", "[REDACTED]"]})
            );
            assert!(!payload.to_string().contains("private provider"));
        }
    }

    #[test]
    fn known_error_codes_explain_what_happened_and_what_to_do() {
        for (method, path, status, code, explanation, next_action) in [
            (
                "POST",
                "/v1/agent/apps/example/reserve",
                503,
                "tier_resolution_unavailable",
                "couldn't check your site allowance, so nothing was changed",
                "Wait a minute, then run the same command again.",
            ),
            (
                "PUT",
                "/v1/agent/apps/example/visibility",
                403,
                "workspace_mismatch",
                "belongs to a different workspace",
                "Run `bl workspace switch`",
            ),
            (
                "PUT",
                "/v1/agent/apps/example/visibility",
                403,
                "owner_required",
                "Only the app's owner can do this.",
                "Ask the app's owner to make the change.",
            ),
            (
                "PUT",
                "/v1/agent/apps/example/access",
                409,
                "access_policy_conflict",
                "changed while this request was running",
                "Run `bl apps get example`",
            ),
            (
                "POST",
                "/v1/agent/apps/example/sharing/communities/buzz-alpha",
                409,
                "community_grant_conflict",
                "community sharing changed at the same time",
                "Run `bl apps get example`",
            ),
            (
                "DELETE",
                "/v1/agent/apps/example/sharing/communities/buzz-alpha",
                403,
                "community_grant_denied",
                "Only the app's owner, signed in to the app's workspace",
                "If you own the app, run `bl workspace switch`",
            ),
        ] {
            let error = control_plane_http_failure(
                method,
                path,
                StatusCode::from_u16(status).unwrap(),
                &json!({"error": {"code": code, "message": "private provider diagnostics"}})
                    .to_string(),
                &test_credential("credential-secret"),
            );
            let (_, payload) = failure_info(&error);
            let message = payload["error"]["message"].as_str().expect("message");
            assert!(message.contains(explanation), "{code}: {message}");
            assert!(
                payload["next_action"]
                    .as_str()
                    .is_some_and(|text| text.starts_with(next_action)),
                "{code}: {payload}"
            );
            assert!(
                message.contains(&format!("next_action: {next_action}")),
                "{code}"
            );
            assert!(!payload.to_string().contains("private provider"));
        }
    }

    #[test]
    fn server_next_action_wins_over_the_cli_explanation_step() {
        let error = control_plane_http_failure(
            "POST",
            "/v1/agent/apps/example/reserve",
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({
                "error": {"code": "tier_resolution_unavailable"},
                "next_action": "Retry after the tier service recovers."
            })
            .to_string(),
            &test_credential("credential-secret"),
        );
        let (_, payload) = failure_info(&error);
        assert_eq!(
            payload["next_action"],
            "Retry after the tier service recovers."
        );
        assert!(payload["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("couldn't check your site allowance")));
    }

    #[test]
    fn unsafe_error_field_keys_do_not_leak_or_replace_typed_errors() {
        for key in ["credential-secret", "unsafe\u{1b}key", "unsafe\u{202e}key"] {
            let field = json!({key: "hidden", "[REDACTED]": "existing"});
            let error = control_plane_http_failure(
                "POST",
                "/v1/agent/apps/example/reserve",
                StatusCode::CONFLICT,
                &json!({
                    "error": {"code": "owner_site_limit_reached", "details": field},
                    "next_action": field
                })
                .to_string(),
                &test_credential("credential-secret"),
            );
            let (_, payload) = failure_info(&error);
            assert_eq!(payload["error"]["code"], "owner_site_limit_reached");
            assert_eq!(payload["error"]["details"], json!({"http_status":409}));
            assert!(payload.get("next_action").is_none());
            assert!(!payload.to_string().contains("hidden"));
        }
    }

    #[test]
    fn recovery_fields_cannot_override_client_diagnostics_or_expose_auth_details() {
        for status in [
            StatusCode::CONFLICT,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
        ] {
            let error = control_plane_http_failure(
                "POST",
                "/v1/agent/apps/example/deploy",
                status,
                &json!({"error": {"code": "owner_site_limit_reached", "details": {
                    "current_count": 10, "http_status": 200,
                    "validation": {"message": "unreviewed diagnostic"}
                }}})
                .to_string(),
                &test_credential("credential-secret"),
            );
            let payload = failure_info(&error).1;
            assert_eq!(payload["error"]["details"]["http_status"], status.as_u16());
            assert!(payload["error"]["details"].get("validation").is_none());
            assert_eq!(
                payload["error"]["details"].get("current_count").is_some(),
                status == StatusCode::CONFLICT
            );
            assert!(!payload.to_string().contains("unreviewed diagnostic"));
        }
    }

    #[test]
    fn successful_response_rejects_secret_bearing_keys_without_collisions() {
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let secret = "reflected_key_session_credential_123456";
        let mut nested = Map::new();
        nested.insert(secret.to_string(), json!("secret-key value"));
        nested.insert("[REDACTED]".to_string(), json!("existing value"));
        let response_body = json!({"nested": Value::Object(nested)}).to_string();
        let server_thread = thread::spawn(move || {
            let request = server.recv().expect("receive request");
            request
                .respond(Response::from_string(response_body))
                .expect("send reflected key response");
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));

        let error = client
            .contract(&test_credential(secret))
            .expect_err("reject a successful response with the session in an object key");
        let message = format!("{error:#}");

        assert!(message.contains("object key"));
        assert!(!message.contains(secret));
        server_thread.join().expect("join request server");
    }

    #[test]
    fn initialize_and_deploy_allow_delayed_rollout_responses() {
        assert!(CONTROL_PLANE_REQUEST_TIMEOUT > Duration::from_secs(2 * 60));

        let temporary_directory = tempfile::tempdir().expect("create temporary directory");
        let artifact_path = temporary_directory.path().join("artifact.tar.gz");
        fs::write(&artifact_path, b"delayed-rollout-artifact").expect("write artifact");
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let server_thread = thread::spawn(move || {
            let initialize = server.recv().expect("receive initialize request");
            assert_eq!(initialize.url(), "/v1/agent/apps/delayed-app/initialize");
            thread::sleep(Duration::from_millis(75));
            initialize
                .respond(
                    Response::from_string(
                        r#"{"ok":true,"app_id":"delayed-app","external_url":"https://delayed-app.example"}"#,
                    )
                    .with_header(
                        Header::from_bytes("Content-Type", "application/json")
                            .expect("build content type"),
                    ),
                )
                .expect("respond to initialize request");

            let mut deploy = server.recv().expect("receive deploy request");
            assert_eq!(deploy.url(), "/v1/agent/apps/delayed-app/deploy");
            let mut body = Vec::new();
            deploy
                .as_reader()
                .read_to_end(&mut body)
                .expect("read deploy body");
            assert!(body
                .windows(b"delayed-rollout-artifact".len())
                .any(|window| window == b"delayed-rollout-artifact"));
            thread::sleep(Duration::from_millis(75));
            deploy
                .respond(
                    Response::from_string(r#"{"ok":true,"version_id":"ver-delayed"}"#).with_header(
                        Header::from_bytes("Content-Type", "application/json")
                            .expect("build content type"),
                    ),
                )
                .expect("respond to deploy request");
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(1));

        let initialized = client
            .initialize(
                &test_credential("delayed_session_credential_123456"),
                "delayed-app",
                &json!({"environment": "staging"}),
            )
            .expect("wait for delayed initialize response");
        let deployed = client
            .deploy(
                &test_credential("delayed_session_credential_123456"),
                "delayed-app",
                &artifact_path,
                &DeployOptions::default(),
            )
            .expect("wait for delayed deploy response");

        assert_eq!(initialized["app_id"], "delayed-app");
        assert_eq!(deployed["version_id"], "ver-delayed");
        server_thread.join().expect("join control-plane server");
    }

    #[test]
    fn control_plane_bounds_plan_responses() {
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let server_thread = thread::spawn(move || {
            let request = server.recv().expect("receive plan request");
            request
                .respond(Response::from_data(vec![
                    b'x';
                    CONTROL_PLANE_RESPONSE_MAX_BYTES
                        + 1
                ]))
                .expect("respond with oversized plan response");
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));
        let request = PlanRequest {
            app_id: Some("bounded-app"),
            name: None,
            environment: None,
            runtime_profile: None,
            persistence: None,
            client_version: "1.0.0",
        };

        let error = client
            .plan(
                &test_credential("bounded_session_credential_123456"),
                &request,
            )
            .expect_err("reject oversized plan response");

        assert!(error.to_string().contains("exceeded 2097152 bytes"));
        assert!(!error
            .to_string()
            .contains("bounded_session_credential_123456"));
        server_thread.join().expect("join control-plane server");
    }

    #[test]
    fn rollback_supports_previous_and_explicit_version_requests() {
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let server_thread = thread::spawn(move || {
            for (expected_path, expected_body) in [
                ("/v1/agent/apps/app%2Fwith%20space/rollback", json!({})),
                (
                    "/v1/agent/apps/app%2Fwith%20space/rollback",
                    json!({
                        "environment": "staging/west?cell=1",
                        "version_id": "ver/123?stable=true"
                    }),
                ),
            ] {
                let mut request = server.recv().expect("receive rollback request");
                assert_eq!(request.method().as_str(), "POST");
                assert_eq!(request.url(), expected_path);
                let mut body = String::new();
                request
                    .as_reader()
                    .read_to_string(&mut body)
                    .expect("read rollback request body");
                assert_eq!(
                    serde_json::from_str::<Value>(&body).expect("parse rollback request body"),
                    expected_body
                );
                request
                    .respond(
                        Response::from_string(r#"{"ok":true}"#).with_header(
                            Header::from_bytes("Content-Type", "application/json")
                                .expect("build content type"),
                        ),
                    )
                    .expect("respond to rollback request");
            }
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));
        let credential = test_credential("rollback_session_credential_123456");

        for request in [
            RollbackRequest {
                environment: None,
                version_id: None,
            },
            RollbackRequest {
                environment: Some("staging/west?cell=1"),
                version_id: Some("ver/123?stable=true"),
            },
        ] {
            client
                .rollback(&credential, "app/with space", &request)
                .expect("request rollback response");
        }

        server_thread.join().expect("join control-plane server");
    }

    #[test]
    fn delete_sends_the_explicit_environment() {
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let server_thread = thread::spawn(move || {
            let mut request = server.recv().expect("receive delete request");
            assert_eq!(request.method().as_str(), "DELETE");
            assert_eq!(request.url(), "/v1/agent/apps/app%2Fwith%20space");
            let mut body = String::new();
            request
                .as_reader()
                .read_to_string(&mut body)
                .expect("read delete request body");
            assert_eq!(
                serde_json::from_str::<Value>(&body).expect("parse delete request body"),
                json!({"environment": "staging/west?cell=1"})
            );
            request
                .respond(
                    Response::from_string(r#"{"ok":true}"#).with_header(
                        Header::from_bytes("Content-Type", "application/json")
                            .expect("build content type"),
                    ),
                )
                .expect("respond to delete request");
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));
        let credential = test_credential("delete_session_credential_123456");

        client
            .delete_app(
                &credential,
                "app/with space",
                &DeleteAppRequest {
                    environment: "staging/west?cell=1",
                },
            )
            .expect("request delete response");

        server_thread.join().expect("join control-plane server");
    }

    #[test]
    fn delete_confirmation_requires_exact_app_and_environment_matches() {
        validate_delete_confirmation("merchant-lookup", "staging", "merchant-lookup", "staging")
            .expect("accept exact delete target confirmation");
        for confirmation in ["different-app", "Merchant-Lookup", "merchant-lookup "] {
            let error =
                validate_delete_confirmation("merchant-lookup", "staging", confirmation, "staging")
                    .expect_err("reject mismatched app id confirmation");
            assert!(error.to_string().contains("exactly match APP_ID"));
            assert!(!error.to_string().contains(confirmation));
        }
        for confirmation in ["production", "Staging", "staging "] {
            let error = validate_delete_confirmation(
                "merchant-lookup",
                "staging",
                "merchant-lookup",
                confirmation,
            )
            .expect_err("reject mismatched environment confirmation");
            assert!(error.to_string().contains("exactly match --environment"));
            assert!(!error.to_string().contains(confirmation));
        }
    }

    #[test]
    fn delete_reports_unknown_outcome_for_an_unreadable_success_response() {
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let server_thread = thread::spawn(move || {
            let request = server.recv().expect("receive delete request");
            assert_eq!(request.method().as_str(), "DELETE");
            request
                .respond(Response::from_string("not-json").with_header(
                    Header::from_bytes(HOTPOD_TRACE_ID_HEADER, REQUEST_TRACE_ID).unwrap(),
                ))
                .expect("respond with unreadable success body");
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));
        let credential_value = "delete_unknown_session_credential_123456";
        let credential = test_credential(credential_value);

        let error = client
            .delete_app(
                &credential,
                "merchant-lookup",
                &DeleteAppRequest {
                    environment: "staging",
                },
            )
            .expect_err("reject unreadable delete success response");
        let (exit_code, payload) = failure_info(&error);
        assert_eq!(exit_code, exit_codes::NETWORK);
        assert_eq!(payload["error"]["trace_id"], REQUEST_TRACE_ID);
        assert_eq!(payload["error"]["code"], "delete_outcome_unknown");
        let message = payload["error"]["message"]
            .as_str()
            .expect("outcome error message");
        assert!(message.contains("may have succeeded"));
        assert!(message.contains("bl apps get <APP_ID> --environment <ENVIRONMENT>"));
        assert!(message.contains("app.status"));
        assert!(!message.contains(credential_value));

        server_thread.join().expect("join control-plane server");
    }

    #[test]
    fn ready_and_debug_build_each_supported_environment_query_shape() {
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let expected_paths = [
            "/v1/agent/apps/app/ready?version_id=ver-123",
            "/v1/agent/apps/app/ready?environment=staging%2Fwest%3Fcell%3D1&version_id=ver%2F123%3Factive",
            "/v1/agent/apps/app/debug",
            "/v1/agent/apps/app/debug?environment=staging%2Fwest%3Fcell%3D1",
            "/v1/agent/apps/app/debug?version_id=ver%2F123%3Factive",
            "/v1/agent/apps/app/debug?tail_lines=25",
            "/v1/agent/apps/app/debug?environment=staging&version_id=ver-123",
            "/v1/agent/apps/app/debug?environment=staging&tail_lines=50",
            "/v1/agent/apps/app/debug?version_id=ver-123&tail_lines=75",
            "/v1/agent/apps/app/debug?environment=staging&version_id=ver-123&tail_lines=100",
        ];
        let server_thread = thread::spawn(move || {
            for (index, expected_path) in expected_paths.into_iter().enumerate() {
                let request = server.recv().expect("receive debug request");
                assert_eq!(request.method().as_str(), "GET");
                assert_eq!(request.url(), expected_path);
                request
                    .respond(
                        Response::from_string(format!(r#"{{"request":{index}}}"#)).with_header(
                            Header::from_bytes("Content-Type", "application/json")
                                .expect("build content type"),
                        ),
                    )
                    .expect("respond to debug request");
            }
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));
        let credential = test_credential("debug_query_session_credential_123456");

        assert_eq!(
            client
                .ready(&credential, "app", "ver-123", None)
                .expect("request default-environment ready response")["request"],
            0
        );
        assert_eq!(
            client
                .ready(
                    &credential,
                    "app",
                    "ver/123?active",
                    Some("staging/west?cell=1"),
                )
                .expect("request explicit-environment ready response")["request"],
            1
        );

        for (index, (environment, version_id, tail_lines)) in [
            (None, None, None),
            (Some("staging/west?cell=1"), None, None),
            (None, Some("ver/123?active"), None),
            (None, None, Some(25)),
            (Some("staging"), Some("ver-123"), None),
            (Some("staging"), None, Some(50)),
            (None, Some("ver-123"), Some(75)),
            (Some("staging"), Some("ver-123"), Some(100)),
        ]
        .into_iter()
        .enumerate()
        {
            let response = client
                .debug(&credential, "app", environment, version_id, tail_lines)
                .expect("request debug response");
            assert_eq!(response["request"], index + 2);
        }

        server_thread.join().expect("join control-plane server");
    }

    #[test]
    fn list_builds_each_supported_query_shape() {
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let expected_paths = [
            "/v1/agent/apps",
            "/v1/agent/apps?scope=owned",
            "/v1/agent/apps?include_deleted=true",
            "/v1/agent/apps?scope=publisher&include_deleted=true",
        ];
        let server_thread = thread::spawn(move || {
            for (index, expected_path) in expected_paths.into_iter().enumerate() {
                let request = server.recv().expect("receive list request");
                assert_eq!(request.method().as_str(), "GET");
                assert_eq!(request.url(), expected_path);
                request
                    .respond(
                        Response::from_string(format!(r#"{{"request":{index}}}"#)).with_header(
                            Header::from_bytes("Content-Type", "application/json")
                                .expect("build content type"),
                        ),
                    )
                    .expect("respond to list request");
            }
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));
        let credential = test_credential("list_query_session_credential_123456");

        for (index, (scope, include_deleted)) in [
            (None, false),
            (Some("owned"), false),
            (None, true),
            (Some("publisher"), true),
        ]
        .into_iter()
        .enumerate()
        {
            let response = client
                .list_apps(&credential, scope, include_deleted)
                .expect("request list response");
            assert_eq!(response["request"], index);
        }

        server_thread.join().expect("join control-plane server");
    }

    #[test]
    fn get_and_versions_support_default_and_explicit_environments() {
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let expected_paths = [
            "/v1/agent/apps/app",
            "/v1/agent/apps/app?environment=staging%2Fwest%3Fcell%3D1",
            "/v1/agent/apps/app/versions",
            "/v1/agent/apps/app/versions?environment=staging%2Fwest%3Fcell%3D1",
        ];
        let server_thread = thread::spawn(move || {
            for (index, expected_path) in expected_paths.into_iter().enumerate() {
                let request = server.recv().expect("receive inspection request");
                assert_eq!(request.method().as_str(), "GET");
                assert_eq!(request.url(), expected_path);
                request
                    .respond(
                        Response::from_string(format!(r#"{{"request":{index}}}"#)).with_header(
                            Header::from_bytes("Content-Type", "application/json")
                                .expect("build content type"),
                        ),
                    )
                    .expect("respond to inspection request");
            }
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));
        let credential = test_credential("inspection_environment_session_credential_123456");

        let responses = [
            client.get_app(&credential, "app", None),
            client.get_app(&credential, "app", Some("staging/west?cell=1")),
            client.versions(&credential, "app", None),
            client.versions(&credential, "app", Some("staging/west?cell=1")),
        ];
        for (index, response) in responses.into_iter().enumerate() {
            assert_eq!(
                response.expect("request inspection response")["request"],
                index
            );
        }

        server_thread.join().expect("join control-plane server");
    }

    #[test]
    fn access_get_and_set_support_each_environment_and_viewer_shape() {
        let server = Server::http("127.0.0.1:0").expect("bind control-plane server");
        let base_url = format!("http://{}", server.server_addr());
        let server_thread = thread::spawn(move || {
            for (index, (method, expected_path, expected_body)) in [
                ("GET", "/v1/agent/apps/app/access", None),
                (
                    "GET",
                    "/v1/agent/apps/app/access?environment=staging%2Fwest%3Fcell%3D1",
                    None,
                ),
                (
                    "PUT",
                    "/v1/agent/apps/app/access",
                    Some(json!({"visibility": "organization", "viewers": []})),
                ),
                (
                    "PUT",
                    "/v1/agent/apps/app/access",
                    Some(json!({
                        "visibility": "restricted",
                        "viewers": ["auth0|alice", "auth0|bob"],
                        "environment": "staging/west?cell=1"
                    })),
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let mut request = server.recv().expect("receive access request");
                assert_eq!(request.method().as_str(), method);
                assert_eq!(request.url(), expected_path);
                let mut body = String::new();
                request
                    .as_reader()
                    .read_to_string(&mut body)
                    .expect("read access request body");
                match expected_body {
                    Some(expected_body) => assert_eq!(
                        serde_json::from_str::<Value>(&body).expect("parse access request body"),
                        expected_body
                    ),
                    None => assert!(body.is_empty(), "GET access body was: {body}"),
                }
                request
                    .respond(
                        Response::from_string(format!(r#"{{"request":{index}}}"#)).with_header(
                            Header::from_bytes("Content-Type", "application/json")
                                .expect("build content type"),
                        ),
                    )
                    .expect("respond to access request");
            }
        });
        let client = test_control_plane_client(&base_url, Duration::from_secs(2));
        let credential = test_credential("access_environment_session_credential_123456");

        let organization = AccessRequest {
            visibility: "organization",
            viewers: vec![],
            environment: None,
        };
        let restricted = AccessRequest {
            visibility: "restricted",
            viewers: vec!["auth0|alice", "auth0|bob"],
            environment: Some("staging/west?cell=1"),
        };
        let responses = [
            client.get_access(&credential, "app", None),
            client.get_access(&credential, "app", Some("staging/west?cell=1")),
            client.set_access(&credential, "app", &organization),
            client.set_access(&credential, "app", &restricted),
        ];
        for (index, response) in responses.into_iter().enumerate() {
            assert_eq!(response.expect("request access response")["request"], index);
        }

        server_thread.join().expect("join control-plane server");
    }

    #[test]
    fn workspace_sharing_is_absent_from_help_and_command_metadata() {
        let mut apps = command();
        assert!(apps.find_subcommand("share").is_none());
        let help = apps.render_long_help().to_string();
        assert!(!help.contains("Share a restricted app with a BuilderLab workspace"));
        let described = describe_commands();
        assert!(!described.to_string().contains("WORKSPACE_ID"));
    }

    #[test]
    fn community_sharing_is_listed_in_help_and_command_metadata() {
        let mut apps = command();
        let community = apps.find_subcommand("community").unwrap();
        assert!(!community.is_hide_set());
        for action in ["grant", "revoke"] {
            let names: Vec<_> = community
                .find_subcommand(action)
                .unwrap()
                .get_positionals()
                .map(|arg| arg.get_id().as_str())
                .collect();
            assert_eq!(names, ["app-id", "community-id"]);
        }
        assert!(apps
            .render_long_help()
            .to_string()
            .contains("\n  community"));
        let described = describe_commands();
        let community = described["commands"]
            .as_array()
            .unwrap()
            .iter()
            .find(|command| command["name"] == "community")
            .expect("community command is described");
        let actions: Vec<_> = community["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|command| command["name"].as_str().unwrap())
            .collect();
        assert_eq!(actions, ["grant", "revoke", "list"]);
    }

    #[test]
    fn bl_apps_handoff_process_without_portal_origin_still_reports_the_audience() {
        let auth = ProcessServer::start(vec![]);
        let control = ProcessServer::start(vec![
            ProcessResponse::json(
                json!({"ok":true,"app":{"app_id":"demo","workspace_id":"owning-workspace","host":"demo.apps.example"}}),
            ),
            ProcessResponse::json(
                json!({"ok":true,"app_id":"demo","visibility":"restricted","viewers":[],"effective_viewers":["owner"],"community_grant_revision":2}),
            ),
        ]);
        let output = process_command(
            &auth,
            &control,
            &["apps", "handoff", "demo", "--json"],
            "apps-e2e-only.unused",
        )
        .env("BL_APPS_E2E_PROXY", "true")
        .env(APPS_BASE_URL_ENV_VAR, "http://compose.mesh.example")
        .output()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let handoff: Value = serde_json::from_str(&process_stdout(&output)).unwrap();
        assert!(handoff["management_url"].is_null());
        assert_eq!(handoff["app_url"], "https://demo.apps.example/");
        assert_eq!(handoff["audience"]["status"], "verified");
        assert_eq!(handoff["audience"]["policy"]["visibility"], "restricted");
        let next_action = handoff["next_action"].as_str().unwrap();
        assert!(next_action.starts_with("Report the current audience beside Open app. "));
        assert!(next_action.contains("There is no Share & manage link on this machine."));
        assert!(next_action
            .contains("Open Hosted Apps in the BuilderLab portal and use Share & manage on demo."));
        assert!(next_action.contains("--management-base-url"));
        assert!(next_action.contains("BL_APPS_MANAGEMENT_BASE_URL"));
        assert!(auth.finish().is_empty());
        let requests = control.finish();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].path, "/v1/agent/apps/demo");
        assert_eq!(requests[1].path, "/v1/agent/apps/demo/access");
    }

    #[test]
    fn bl_apps_handoff_process_treats_a_blank_portal_as_unset_and_prefers_the_flag() {
        for (flag, env, expected) in [
            (None, Some(""), None),
            (None, Some("   "), None),
            (Some(""), None, None),
            (
                Some("https://flag.example"),
                Some("http://invalid-env.example"),
                Some("https://flag.example/hosted-apps?app=demo&workspace=owning-workspace"),
            ),
            (
                Some("https://flag.example"),
                Some("https://env.example"),
                Some("https://flag.example/hosted-apps?app=demo&workspace=owning-workspace"),
            ),
        ] {
            let auth = ProcessServer::start(vec![]);
            let control = ProcessServer::start(vec![
                ProcessResponse::json(
                    json!({"ok":true,"app":{"app_id":"demo","workspace_id":"owning-workspace","host":"demo.apps.example"}}),
                ),
                ProcessResponse::json(
                    json!({"ok":true,"app_id":"demo","visibility":"organization","viewers":[],"community_grant_revision":2}),
                ),
            ]);
            let mut args = vec!["apps", "handoff", "demo", "--json"];
            if let Some(flag) = flag {
                args.extend(["--management-base-url", flag]);
            }
            let mut command = process_command(&auth, &control, &args, "apps-e2e-only.unused");
            command
                .env("BL_APPS_E2E_PROXY", "true")
                .env(APPS_BASE_URL_ENV_VAR, "http://compose.mesh.example");
            if let Some(env) = env {
                command.env("BL_APPS_MANAGEMENT_BASE_URL", env);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{flag:?} {env:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let handoff: Value = serde_json::from_str(&process_stdout(&output)).unwrap();
            assert_eq!(
                handoff["management_url"],
                json!(expected),
                "{flag:?} {env:?}"
            );
            assert_eq!(handoff["audience"]["status"], "verified");
            assert!(auth.finish().is_empty());
            assert_eq!(control.finish().len(), 2);
        }
    }

    #[test]
    fn bl_apps_handoff_process_still_rejects_an_invalid_portal_flag_before_any_request() {
        for (flag, env) in [
            (Some("https://app.example/path"), None),
            // The flag wins, so a good environment value doesn't rescue a bad flag.
            (
                Some("http://app.example"),
                Some("https://app.builderlab.xyz"),
            ),
        ] {
            let auth = ProcessServer::start(vec![]);
            let control = ProcessServer::start(vec![]);
            let mut args = vec!["apps", "handoff", "demo", "--json"];
            if let Some(flag) = flag {
                args.extend(["--management-base-url", flag]);
            }
            let mut command = process_command(&auth, &control, &args, "apps-e2e-only.unused");
            command
                .env("BL_APPS_E2E_PROXY", "true")
                .env(APPS_BASE_URL_ENV_VAR, "http://compose.mesh.example");
            if let Some(env) = env {
                command.env("BL_APPS_MANAGEMENT_BASE_URL", env);
            }
            let output = command.output().unwrap();
            assert!(!output.status.success());
            let message = process_error(&output)["error"]["message"]
                .as_str()
                .unwrap()
                .to_string();
            assert!(message.contains("management base URL must be an HTTPS portal origin"));
            assert!(auth.finish().is_empty());
            assert!(control.finish().is_empty());
        }
    }

    #[test]
    fn bl_apps_get_with_a_stale_portal_variable_drops_only_the_link() {
        for json_output in [true, false] {
            let auth = ProcessServer::start(vec![]);
            let control = ProcessServer::start(vec![
                ProcessResponse::json(
                    json!({"ok":true,"app":{"app_id":"demo","workspace_id":"owning-workspace"}}),
                ),
                ProcessResponse::json(
                    json!({"ok":true,"app_id":"demo","visibility":"organization","viewers":[],"community_grant_revision":2}),
                ),
            ]);
            let mut args = vec!["apps", "get", "demo"];
            if json_output {
                args.push("--json");
            }
            let output = process_command(&auth, &control, &args, "apps-e2e-only.unused")
                .env("BL_APPS_E2E_PROXY", "true")
                .env(APPS_BASE_URL_ENV_VAR, "http://compose.mesh.example")
                .env("BL_APPS_MANAGEMENT_BASE_URL", "http://localhost:3000")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = process_stdout(&output);
            if json_output {
                let got: Value = serde_json::from_str(&stdout).unwrap();
                assert!(got["management_url"].is_null());
                assert_eq!(got["audience"]["status"], "verified");
                assert!(got["next_action"]
                    .as_str()
                    .unwrap()
                    .ends_with(UNUSABLE_MANAGEMENT_BASE_URL));
            } else {
                assert!(stdout.contains("Who can open it: Everyone in the app's workspace."));
                assert!(
                    stdout.ends_with(&format!("Note: {UNUSABLE_MANAGEMENT_BASE_URL}")),
                    "{stdout}"
                );
            }
            assert!(auth.finish().is_empty());
            assert_eq!(control.finish().len(), 2);
        }
    }

    #[test]
    fn bl_apps_community_list_sends_the_session_and_redacts_it_from_output() {
        let credential = "apps-e2e-only.community-list.session";
        for json_output in [false, true] {
            let auth_server = ProcessServer::start(vec![ProcessResponse::json(json!({
                "communities": [
                    {"id": "buzz-alpha", "name": format!("Alpha {credential}"), "normalizedHost": "alpha.example"}
                ]
            }))]);
            let control_plane = ProcessServer::start(vec![]);
            let mut args = vec!["apps", "community", "list"];
            if json_output {
                args.push("--json");
            }
            let output = process_command(&auth_server, &control_plane, &args, credential)
                .output()
                .expect("run community list process");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = process_stdout(&output);
            assert!(!stdout.contains(credential), "{stdout}");
            if json_output {
                let got: Value = serde_json::from_str(&stdout).unwrap();
                assert_eq!(got["communities"][0]["community_id"], "buzz-alpha");
                assert_eq!(got["communities"][0]["name"], "Alpha [REDACTED]");
                assert_eq!(got["communities"][0]["host"], "alpha.example");
            } else {
                assert!(
                    stdout.starts_with("buzz-alpha  Alpha [REDACTED] (alpha.example)\n"),
                    "{stdout}"
                );
            }
            let requests = auth_server.finish();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].method, "POST");
            assert_eq!(
                requests[0].path,
                format!("/api/goose{JOINED_COMMUNITIES_PATH}")
            );
            assert_eq!(
                requests[0]
                    .headers
                    .get("x-bb-session-credential")
                    .map(String::as_str),
                Some(credential)
            );
            assert!(control_plane.finish().is_empty());
        }
    }

    #[test]
    fn community_names_ask_kgoose_only_when_a_community_is_shared() {
        for ids in [None, Some(Value::Null), Some(json!([]))] {
            let names =
                community_names_with(ids.as_ref(), || panic!("looked up names for {ids:?}"));
            assert!(names.is_empty());
        }
        let ids = json!(["buzz-alpha"]);
        let names = community_names_with(Some(&ids), || {
            Ok(vec![
                json!({"community_id":"buzz-alpha","name":"Alpha Team"}),
            ])
        });
        assert_eq!(names["buzz-alpha"], "Alpha Team");
        // A failed lookup only loses the names.
        let names = community_names_with(Some(&ids), || anyhow::bail!("kgoose down"));
        assert!(names.is_empty());
    }

    #[test]
    fn bl_apps_community_grant_reads_only_the_target_grant_before_post() {
        let credential = "apps-e2e-only.community.session";
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        // The sharing read returns only CAS inputs, not the app's access policy.
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(json!({
                "ok": true,
                "app_id": "my-app",
                "lifecycle_id": "life-123",
                "community_grant_revision": 7,
            })),
            ProcessResponse::json(json!({"ok": true, "community_grant_revision": 8})),
        ]);
        let output = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "community",
                "grant",
                "my-app",
                "buzz-alpha",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--json",
            ],
            credential,
        )
        .output()
        .expect("run community grant process");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let auth_requests = auth_server.finish();
        assert_eq!(auth_requests.len(), 1);
        assert_process_auth(&auth_requests[0], credential);
        let requests = control_plane.finish();
        assert_eq!(requests.len(), 2);
        let path = "/v1/agent/apps/my-app/sharing/communities/buzz-alpha";
        assert_process_control_plane(&requests[0], "GET", path, credential);
        assert_process_control_plane(&requests[1], "POST", path, credential);
        assert_eq!(
            requests[1].body,
            json!({"lifecycle_id": "life-123", "expected_revision": 7})
        );
    }

    #[test]
    fn bl_apps_community_refuses_the_blox_proxy_before_any_request() {
        // The proxy would forward an owner credential that Compose rejects for
        // community routes, so the CLI stops before authenticating or reading.
        for action in ["grant", "revoke"] {
            let auth_server = ProcessServer::start(vec![]);
            let control_plane = ProcessServer::start(vec![]);
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "community",
                    action,
                    "my-app",
                    "buzz-alpha",
                    "--json",
                ],
                "apps-e2e-only.unused",
            )
            .env("BL_APPS_E2E_PROXY", "true")
            .env(APPS_BASE_URL_ENV_VAR, "http://compose.mesh.example")
            .output()
            .expect("run proxied community process");
            assert!(!output.status.success());
            let error = process_error(&output);
            assert_eq!(
                error["error"]["code"],
                "community_sharing_unavailable_through_proxy"
            );
            assert!(error["next_action"]
                .as_str()
                .is_some_and(|action| action.contains("Share & manage")));
            assert!(auth_server.finish().is_empty());
            assert!(control_plane.finish().is_empty());
        }
    }

    #[test]
    fn bl_apps_community_proxy_refusal_links_share_and_manage_when_the_portal_is_known() {
        let auth_server = ProcessServer::start(vec![]);
        let control_plane = ProcessServer::start(vec![]);
        let output = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "community",
                "grant",
                "my-app",
                "buzz-alpha",
                "--json",
            ],
            "apps-e2e-only.unused",
        )
        .env("BL_APPS_E2E_PROXY", "true")
        .env(APPS_BASE_URL_ENV_VAR, "http://compose.mesh.example")
        .env("BL_APPS_MANAGEMENT_BASE_URL", "https://app.builderlab.xyz")
        .output()
        .expect("run proxied community process");
        let error = process_error(&output);
        assert_eq!(
            error["error"]["code"],
            "community_sharing_unavailable_through_proxy"
        );
        let next_action = error["next_action"].as_str().unwrap();
        // The portal only opens an app's dialog when it also gets the workspace.
        assert!(next_action.contains(
            "Open Share & manage at https://app.builderlab.xyz/hosted-apps and choose my-app."
        ));
        assert!(!next_action.contains("app="));
        assert!(error["error"]["message"]
            .as_str()
            .unwrap()
            .contains(next_action));
        assert!(auth_server.finish().is_empty());
        assert!(control_plane.finish().is_empty());
    }

    #[test]
    fn bl_apps_community_proxy_refusal_points_to_the_browser_dialog_without_a_portal() {
        let auth_server = ProcessServer::start(vec![]);
        let control_plane = ProcessServer::start(vec![]);
        let output = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "community",
                "grant",
                "my-app",
                "buzz-alpha",
                "--json",
            ],
            "apps-e2e-only.unused",
        )
        .env("BL_APPS_E2E_PROXY", "true")
        .env(APPS_BASE_URL_ENV_VAR, "http://compose.mesh.example")
        .output()
        .expect("run proxied community process");
        let error = process_error(&output);
        let next_action = error["next_action"].as_str().unwrap();
        assert!(next_action.contains(
            "Open Hosted Apps in the BuilderLab portal and use Share & manage on my-app."
        ));
        assert!(!next_action.contains("https://"));
        assert!(error["error"]["message"]
            .as_str()
            .unwrap()
            .contains(next_action));
    }

    #[test]
    fn bl_apps_community_without_a_lifecycle_tells_the_owner_to_deploy_first() {
        // Compose answers the grant read with 409 when the app has no sharing
        // lifecycle; an empty lifecycle on a 200 is guarded the same way.
        let conflict = || {
            ProcessResponse::raw(
                409,
                json!({"error": {"code": "community_grant_conflict"}}).to_string(),
            )
            .with_trace_id(REQUEST_TRACE_ID)
        };
        let empty = || {
            ProcessResponse::json(json!({"ok": true, "community_grant_revision": 7}))
                .with_trace_id(REQUEST_TRACE_ID)
        };
        for (read, code) in [
            (conflict(), "community_grant_conflict"),
            (empty(), "app_sharing_lifecycle_missing"),
        ] {
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let control_plane = ProcessServer::start(vec![read]);
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "community",
                    "grant",
                    "my-app",
                    "buzz-alpha",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                    "--json",
                ],
                "apps-e2e-only.no-lifecycle.session",
            )
            .env("BL_APPS_MANAGEMENT_BASE_URL", "https://app.builderlab.xyz")
            .output()
            .expect("run community without lifecycle");
            let error = process_error(&output);
            assert_eq!(error["error"]["code"], code);
            assert_eq!(error["error"]["trace_id"], REQUEST_TRACE_ID);
            let next_action = error["next_action"].as_str().unwrap();
            assert_eq!(
                next_action,
                "my-app has no sharing lifecycle yet. Deploy it with `bl apps deploy`, then retry."
            );
            assert!(error["error"]["message"]
                .as_str()
                .unwrap()
                .ends_with(&format!("next_action: {next_action}")));
            auth_server.finish();
            assert_eq!(
                control_plane.finish().len(),
                1,
                "never mutate without a lifecycle"
            );
        }
    }

    #[test]
    fn bl_apps_community_grant_preserves_server_denials_and_does_not_retry() {
        for (read_denied, status, code) in [
            (true, 403, "community_grant_denied"),
            (false, 403, "community_grant_denied"),
            (false, 409, "community_grant_conflict"),
        ] {
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let denied = ProcessResponse::raw(status, json!({"error": {"code": code}}).to_string())
                .with_trace_id(REQUEST_TRACE_ID);
            let mut responses = vec![];
            if !read_denied {
                responses.push(ProcessResponse::json(json!({
                    "ok": true,
                    "lifecycle_id": "life-123",
                    "community_grant_revision": 7,
                })));
            }
            responses.push(denied);
            let control_plane = ProcessServer::start(responses);
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "community",
                    "grant",
                    "my-app",
                    "buzz-alpha",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                    "--json",
                ],
                "apps-e2e-only.denied-community.session",
            )
            .output()
            .expect("run denied community grant process");
            assert!(!output.status.success());
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.contains(code), "{stderr}");
            assert!(stderr.contains(REQUEST_TRACE_ID), "{stderr}");
            auth_server.finish();
            let requests = control_plane.finish();
            assert_eq!(requests.len(), if read_denied { 1 } else { 2 });
            let path = "/v1/agent/apps/my-app/sharing/communities/buzz-alpha";
            assert_eq!(requests[0].method, "GET");
            assert_eq!(requests[0].path, path);
            if !read_denied {
                assert_eq!(requests[1].method, "POST");
                assert_eq!(requests[1].path, path);
            }
        }
    }

    #[test]
    fn bl_apps_community_revoke_reads_only_the_target_grant_before_delete() {
        let credential = "apps-e2e-only.revoke.session+credential";
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(json!({
                "ok": true,
                "app_id": "my-app",
                "lifecycle_id": "life-123",
                "community_grant_revision": 7,
            })),
            ProcessResponse::json(json!({"ok": true, "community_grant_revision": 8})),
        ]);
        let mut command = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "community",
                "revoke",
                "my-app",
                "buzz-former",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
            ],
            credential,
        );
        let output = command
            .output()
            .expect("run community revoke process command");
        assert!(
            output.status.success(),
            "stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let auth_requests = auth_server.finish();
        assert_eq!(auth_requests.len(), 1);
        assert_process_auth(&auth_requests[0], credential);
        let requests = control_plane.finish();
        assert_eq!(requests.len(), 2);
        let path = "/v1/agent/apps/my-app/sharing/communities/buzz-former";
        assert_process_control_plane(&requests[0], "GET", path, credential);
        assert_process_control_plane(&requests[1], "DELETE", path, credential);
        assert_eq!(
            requests[1].body,
            json!({"lifecycle_id":"life-123","expected_revision":7})
        );
    }

    #[test]
    fn bl_apps_community_process_retains_trace_on_validation_failures() {
        for body in [
            json!({}),
            json!({"lifecycle_id":"life-123"}),
            json!({"lifecycle_id":"life-123", "community_grant_revision":-1}),
        ] {
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let control_plane = ProcessServer::start(vec![
                ProcessResponse::json(body).with_trace_id(REQUEST_TRACE_ID)
            ]);
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "community",
                    "grant",
                    "app",
                    "buzz-test",
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                    "--client-version",
                    "0.2.0",
                    "--json",
                ],
                "apps-e2e-only.trace-community.session",
            )
            .output()
            .expect("run invalid community command");
            assert_eq!(
                process_error(&output)["error"]["trace_id"],
                REQUEST_TRACE_ID
            );
            auth_server.finish();
            assert_eq!(
                control_plane.finish().len(),
                1,
                "never mutate invalid sharing state"
            );
        }
    }

    #[test]
    fn retired_workspace_sharing_never_authenticates_or_reaches_compose() {
        for action in ["grant", "revoke"] {
            let auth_server = ProcessServer::start(vec![]);
            let control_plane = ProcessServer::start(vec![]);
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "share",
                    action,
                    "my-app",
                    "target-workspace",
                    "--json",
                ],
                "apps-e2e-only.retired-share.session",
            )
            .output()
            .expect("run retired sharing command");
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("share"), "{stderr}");
            assert!(auth_server.finish().is_empty());
            assert!(control_plane.finish().is_empty());
        }
    }

    fn private_create_plan() -> Value {
        json!({
            "app_id": "merchant-lookup",
            "environment": "staging",
            "persistence": "sqlite",
            "runtime_profile": "fetch-js",
            "runtime_class": "default",
            "initialize": {"required": true, "recommended": false}
        })
    }

    fn private_create_command(
        auth_server: &ProcessServer,
        control_plane: &ProcessServer,
        credential: &str,
    ) -> ProcessCommand {
        process_command(
            auth_server,
            control_plane,
            &[
                "apps",
                "create",
                "--app-id",
                "merchant-lookup",
                "--environment",
                "staging",
                "--private",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--client-version",
                "0.2.0",
                "--json",
            ],
            credential,
        )
    }

    #[test]
    fn bl_apps_create_private_sets_visibility_after_reserve_and_before_initialize() {
        let credential = "apps-e2e-only.private.session+credential";
        let visibility = json!({
            "ok": true,
            "app_id": "merchant-lookup",
            "visibility": "restricted",
            "viewers": [],
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(private_create_plan()),
            ProcessResponse::json(json!({"app_id": "merchant-lookup"})),
            ProcessResponse::json(visibility.clone()),
            ProcessResponse::json(json!({
                "app_id": "merchant-lookup",
                "external_url": "https://merchant-lookup--bpsites.example/"
            })),
        ]);
        let output = private_create_command(&auth_server, &control_plane, credential)
            .output()
            .expect("run private create process");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value = serde_json::from_str::<Value>(&process_stdout(&output)).unwrap();
        assert_eq!(value["visibility"], visibility);
        assert_eq!(value["initialized"], true);
        assert_process_auth(&auth_server.finish()[0], credential);
        let requests = control_plane.finish();
        let order: Vec<_> = requests
            .iter()
            .map(|request| (request.method.as_str(), request.path.as_str()))
            .collect();
        assert_eq!(
            order,
            [
                ("POST", APPS_PLAN_PATH),
                ("POST", "/v1/agent/apps/merchant-lookup/reserve"),
                ("PUT", "/v1/agent/apps/merchant-lookup/visibility"),
                ("POST", "/v1/agent/apps/merchant-lookup/initialize"),
            ]
        );
        assert_process_control_plane(
            &requests[2],
            "PUT",
            "/v1/agent/apps/merchant-lookup/visibility",
            credential,
        );
        assert_eq!(
            requests[2].body,
            json!({"visibility": "restricted", "environment": "staging"})
        );
    }

    #[test]
    fn bl_apps_create_private_stops_before_initialize_when_app_is_not_private() {
        for (response, expected) in [
            (
                ProcessResponse::raw(403, json!({"error": {"code": "access_denied"}}).to_string())
                    .with_trace_id(REQUEST_TRACE_ID),
                "access_denied",
            ),
            (
                ProcessResponse::json(json!({
                    "ok": true,
                    "app_id": "merchant-lookup",
                    "visibility": "organization",
                })),
                "Apps Platform visibility returned",
            ),
            (
                ProcessResponse::json(json!({
                    "ok": true,
                    "app_id": "other-app",
                    "visibility": "restricted",
                })),
                "No replacement app was accepted",
            ),
        ] {
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let control_plane = ProcessServer::start(vec![
                ProcessResponse::json(private_create_plan()),
                ProcessResponse::json(json!({"app_id": "merchant-lookup"})),
                response,
            ]);
            let output = private_create_command(
                &auth_server,
                &control_plane,
                "apps-e2e-only.private-denied.session",
            )
            .output()
            .expect("run failed private create process");
            assert!(!output.status.success());
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(
                stderr.contains("did not make it private. Do not deploy it."),
                "{stderr}"
            );
            assert!(
                stderr.contains("run `bl apps visibility merchant-lookup private`"),
                "{stderr}"
            );
            assert!(stderr.contains(expected), "{stderr}");
            auth_server.finish();
            let requests = control_plane.finish();
            assert_eq!(
                requests.len(),
                3,
                "no initialize after a failed private setup"
            );
            assert_eq!(requests[2].method, "PUT");
            assert_eq!(
                requests[2].path,
                "/v1/agent/apps/merchant-lookup/visibility"
            );
        }
    }

    #[test]
    fn bl_apps_create_private_retry_reconciles_the_reservation_then_makes_it_private() {
        let credential = "apps-e2e-only.private-retry.session";
        let collision = ProcessResponse::json_status(
            409,
            json!({"ok": false, "error": {"code": "app_id_collision"}}),
        );
        // Setting visibility leaves route_revision at 1, so the earlier
        // reservation still matches on retry.
        let existing_reservation = json!({
            "ok": true,
            "app": {
                "app_id": "merchant-lookup",
                "environment": "staging",
                "persistence": "sqlite",
                "runtime_class": "default",
                "runtime_profile": "fetch-js",
                "role": "owner",
                "status": "idle",
                "route_status": "idle",
                "route_revision": 1
            },
            "versions": []
        });
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![
            ProcessResponse::json(private_create_plan()),
            collision,
            ProcessResponse::json(existing_reservation),
            ProcessResponse::json(json!({
                "ok": true,
                "app_id": "merchant-lookup",
                "visibility": "restricted",
                "viewers": [],
            })),
            ProcessResponse::json(json!({
                "app_id": "merchant-lookup",
                "external_url": "https://merchant-lookup--bpsites.example/"
            })),
        ]);
        let output = private_create_command(&auth_server, &control_plane, credential)
            .output()
            .expect("run private create retry process");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value = serde_json::from_str::<Value>(&process_stdout(&output)).unwrap();
        assert_eq!(value["reservation_reconciled"], true);
        assert_eq!(value["visibility"]["visibility"], "restricted");
        auth_server.finish();
        let order: Vec<_> = control_plane
            .finish()
            .into_iter()
            .map(|request| (request.method, request.path))
            .collect();
        let path = |path: &str| path.to_string();
        assert_eq!(
            order,
            [
                (path("POST"), path(APPS_PLAN_PATH)),
                (path("POST"), path("/v1/agent/apps/merchant-lookup/reserve")),
                (
                    path("GET"),
                    path("/v1/agent/apps/merchant-lookup?environment=staging")
                ),
                (
                    path("PUT"),
                    path("/v1/agent/apps/merchant-lookup/visibility")
                ),
                (
                    path("POST"),
                    path("/v1/agent/apps/merchant-lookup/initialize")
                ),
            ]
        );
    }

    #[test]
    fn bl_apps_visibility_switches_only_the_base_audience() {
        for (audience, visibility) in [("workspace", "organization"), ("private", "restricted")] {
            let credential = "apps-e2e-only.visibility.session";
            let updated = json!({
                "ok": true,
                "app_id": "my-app",
                "visibility": visibility,
                "viewers": ["carol"],
                "shared_communities": ["buzz-alpha"],
            });
            let auth_server = ProcessServer::start(vec![process_auth_response()]);
            let control_plane = ProcessServer::start(vec![ProcessResponse::json(updated.clone())]);
            let output = process_command(
                &auth_server,
                &control_plane,
                &[
                    "apps",
                    "visibility",
                    "my-app",
                    audience,
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                    "--json",
                ],
                credential,
            )
            .output()
            .expect("run visibility process");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let value = serde_json::from_str::<Value>(&process_stdout(&output)).unwrap();
            assert_eq!(value, updated);
            assert_process_auth(&auth_server.finish()[0], credential);
            let requests = control_plane.finish();
            assert_eq!(requests.len(), 1);
            let path = "/v1/agent/apps/my-app/visibility";
            assert_process_control_plane(&requests[0], "PUT", path, credential);
            // Only the visibility is sent, so viewers and grants are never replaced.
            assert_eq!(requests[0].body, json!({"visibility": visibility}));
        }
    }

    #[test]
    fn bl_apps_visibility_rejects_a_response_for_another_audience() {
        let auth_server = ProcessServer::start(vec![process_auth_response()]);
        let control_plane = ProcessServer::start(vec![ProcessResponse::json(json!({
            "ok": true,
            "app_id": "my-app",
            "visibility": "organization",
        }))]);
        let output = process_command(
            &auth_server,
            &control_plane,
            &[
                "apps",
                "visibility",
                "my-app",
                "private",
                "--base-url",
                APPROVED_TEST_BASE_URL,
                "--json",
            ],
            "apps-e2e-only.visibility-mismatch.session",
        )
        .output()
        .expect("run mismatched visibility process");
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("Apps Platform visibility returned"),
            "{stderr}"
        );
        auth_server.finish();
        assert_eq!(control_plane.finish().len(), 1);
    }

    #[test]
    fn visibility_accepts_only_user_facing_audiences_before_auth_or_network() {
        for audience in ["organization", "restricted", "public"] {
            let error = command()
                .try_get_matches_from([
                    "apps",
                    "visibility",
                    "app",
                    audience,
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                ])
                .expect_err("reject internal or unknown audience");
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
        }
        let mut apps = command();
        let help = apps.render_long_help().to_string();
        assert!(help.contains("\n  visibility"), "{help}");
        let create = apps.find_subcommand_mut("create").unwrap();
        assert!(create.render_long_help().to_string().contains("--private"));
        let described = describe_commands();
        assert!(described["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|command| command["name"] == "visibility"));
    }

    #[test]
    fn access_set_rejects_unknown_visibility_before_auth_or_network() {
        let error = command()
            .try_get_matches_from([
                "apps",
                "access",
                "set",
                "app",
                "--visibility",
                "public",
                "--base-url",
                APPROVED_TEST_BASE_URL,
            ])
            .expect_err("reject unknown access visibility");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn debug_tail_lines_match_control_plane_bounds() {
        for invalid in ["0", "1001"] {
            let error = command()
                .try_get_matches_from([
                    "apps",
                    "debug",
                    "app",
                    "--tail-lines",
                    invalid,
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                ])
                .expect_err("reject out-of-range tail lines");
            assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        }

        for valid in ["1", "1000"] {
            command()
                .try_get_matches_from([
                    "apps",
                    "debug",
                    "app",
                    "--tail-lines",
                    valid,
                    "--base-url",
                    APPROVED_TEST_BASE_URL,
                ])
                .expect("accept bounded tail lines");
        }
    }

    #[test]
    fn app_resource_urls_encode_path_segments_and_query_values() {
        let client = test_control_plane_client("http://127.0.0.1:9", Duration::from_secs(2));

        let url = client
            .app_action_url("app/../../identity", "deploy")
            .expect("build app deploy URL");

        assert_eq!(url.path(), "/v1/agent/apps/app%2F..%2F..%2Fidentity/deploy");

        let app = client
            .app_url("app/with space", &[])
            .expect("build app detail URL");
        assert_eq!(app.path(), "/v1/agent/apps/app%2Fwith%20space");

        let ready = client
            .app_resource_url(
                "app/with space",
                "ready",
                &[("version_id", "version/?&= value".to_string())],
            )
            .expect("build app ready URL");
        assert_eq!(
            request_path(&ready),
            "/v1/agent/apps/app%2Fwith%20space/ready?version_id=version%2F%3F%26%3D+value"
        );
    }
}
