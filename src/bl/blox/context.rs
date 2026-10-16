use crate::bl::auth_login::verify_stored_session;
use crate::bl::auth_storage::default_session_storage;
use crate::bl::display::terminal_safe_text;
use crate::bl::runner;
use crate::bl::skills_api::{exit_codes, failure};
use crate::bl::skills_config::SkillsConfig;
use anyhow::{Context, Result};
use blox::proto::WorkstationSummary;
use clap::{Arg, ArgMatches, Command};
const ENDPOINT_ENV: &str = "BL_BLOX_CONTROL_PLANE_URL";
const APPROVED_HOSTS: &[&str] = &[
    "blox.test.blockstaging.build",
    "blox.public.builderlabstaging.xyz",
    "blox.public.builderlab.xyz",
    "blox.builderlab.xyz",
];

pub(super) fn args(command: Command) -> Command {
    command.arg(
        Arg::new("blox-base-url")
            .long("base-url")
            .visible_alias("control-plane-url")
            .env(ENDPOINT_ENV)
            .global(true)
            .value_name("URL")
            .help(
                "Approved BuilderLab Blox control-plane URL (defaults to your login environment)",
            ),
    )
}

pub(super) fn client(
    config: &SkillsConfig,
    args: &ArgMatches,
    operation: &str,
) -> Result<blox::Client> {
    let endpoint = args
        .get_one::<String>("blox-base-url")
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| default_endpoint(&config.kgoose_base_url))?;
    validate_endpoint(&endpoint)?;
    runner::ensure_org_configured(config)?;
    let storage = default_session_storage(config)?;
    let verified = verify_stored_session(config, storage.as_ref())
        .map_err(map_error)?
        .ok_or_else(|| {
            failure(
                exit_codes::AUTH_REQUIRED,
                "auth_required",
                "BuilderLab CLI auth is required; run `bl auth login`",
            )
        })?;
    let secret = verified
        .credential
        .session_credential_header_value()
        .ok_or_else(|| {
            failure(
                exit_codes::AUTH_REQUIRED,
                "auth_required",
                "BuilderLab CLI auth is required; run `bl auth login`",
            )
        })?;
    // Test-only remapping leaves production origin validation and auth intact.
    #[cfg(test)]
    let endpoint = std::env::var("BL_BLOX_E2E_ENDPOINT").unwrap_or(endpoint);
    let client = blox::Client::new(&endpoint)?.with_session_credential(&secret)?;
    config.style.verbose(&format!("Blox {operation}"));
    Ok(client)
}

pub(super) fn workstation(client: &blox::Client, args: &ArgMatches) -> Result<WorkstationSummary> {
    let selector = args
        .get_one::<String>("workstation")
        .context("expected workstation")?;
    let workstation = client
        .get_workstation(selector)
        .map_err(map_error)?
        .workstation
        .filter(|workstation| !workstation.workstation_id.is_empty())
        .ok_or_else(|| {
            failure(
                exit_codes::GENERAL,
                "invalid_response",
                "Blox returned no workstation ID",
            )
        })?;

    Ok(workstation)
}

fn default_endpoint(auth_base_url: &str) -> Result<String> {
    let origin = url::Url::parse(auth_base_url)
        .context("parse BuilderLab auth URL")?
        .origin()
        .ascii_serialization();
    let endpoint = match origin.as_str() {
        "https://test.blockstaging.build" => "https://blox.test.blockstaging.build",
        "https://app.builderlabstaging.xyz" => "https://blox.public.builderlabstaging.xyz",
        "https://app.builderlab.xyz" => "https://blox.builderlab.xyz",
        "https://block.builderlab.xyz" => return Err(failure(exit_codes::GENERAL, "blox_unavailable", "Blox is not deployed in this BuilderLab environment")),
        _ => return Err(failure(exit_codes::GENERAL, "endpoint_required", "No Blox endpoint is configured for this BuilderLab environment; set an approved ingress with --base-url or BL_BLOX_CONTROL_PLANE_URL")),
    };
    Ok(endpoint.to_string())
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    let url = url::Url::parse(endpoint).context("parse Blox control-plane URL")?;
    let approved = url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.host_str().is_some_and(|host| {
            APPROVED_HOSTS
                .iter()
                .any(|approved| host.eq_ignore_ascii_case(approved))
        });
    if !approved {
        return Err(failure(
            exit_codes::GENERAL,
            "invalid_endpoint",
            "Blox control-plane URL must target an approved BuilderLab ingress over HTTPS",
        ));
    }
    Ok(())
}

pub(super) fn map_error(error: anyhow::Error) -> anyhow::Error {
    if let Some(rpc) = error.downcast_ref::<blox::RpcError>() {
        let exit_code = match rpc.code.as_str() {
            "unauthenticated" => exit_codes::AUTH_REQUIRED,
            "permission_denied" => exit_codes::FORBIDDEN,
            "unavailable" | "deadline_exceeded" => exit_codes::NETWORK,
            _ => exit_codes::GENERAL,
        };
        let message = if rpc.code == "unauthenticated" {
            "Blox authentication failed; run `bl auth login`".to_string()
        } else {
            format!("Blox {}: {}", rpc.code, terminal_safe_text(&rpc.message))
        };
        return failure(exit_code, &rpc.code, message);
    }
    if error.chain().any(|cause| cause.is::<reqwest::Error>()) {
        return failure(exit_codes::NETWORK, "network_error", format!("{error:#}"));
    }
    error
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_follow_exact_login_origins() {
        for (auth, blox) in [
            (
                "https://test.blockstaging.build",
                "https://blox.test.blockstaging.build",
            ),
            (
                "https://app.builderlabstaging.xyz",
                "https://blox.public.builderlabstaging.xyz",
            ),
            ("https://app.builderlab.xyz", "https://blox.builderlab.xyz"),
        ] {
            assert_eq!(default_endpoint(auth).unwrap(), blox);
            assert!(validate_endpoint(blox).is_ok());
        }
        assert!(validate_endpoint("https://blox.public.builderlab.xyz").is_ok());
        assert!(default_endpoint("https://block.builderlab.xyz")
            .unwrap_err()
            .to_string()
            .contains("not deployed"));
        for origin in [
            "http://app.builderlab.xyz",
            "https://app.builderlab.xyz:8443",
            "https://app.builderlab.xyz.evil.test",
        ] {
            assert!(default_endpoint(origin).is_err());
        }
    }

    #[test]
    fn session_origin_validation_rejects_unapproved_destinations() {
        for endpoint in [
            "http://blox.public.builderlab.xyz",
            "https://blox.public.builderlab.xyz:8443",
            "https://blox.public.builderlab.xyz.evil.test",
            "https://user@blox.public.builderlab.xyz",
            "https://blox.public.builderlab.xyz/path",
            "https://blox.public.builderlab.xyz/?q=1",
            "https://blox.public.builderlab.xyz/#fragment",
            "http://blox.builderlab.xyz",
            "https://blox.builderlab.xyz:8443",
            "https://blox.builderlab.xyz.evil.test",
            "https://user@blox.builderlab.xyz",
            "https://blox.builderlab.xyz/path",
            "https://blox.builderlab.xyz/?q=1",
            "https://blox.builderlab.xyz/#fragment",
            "http://127.0.0.1:8895",
        ] {
            assert!(validate_endpoint(endpoint).is_err(), "accepted {endpoint}");
        }
    }
}
