use super::context::map_error as map_rpc_error;
use super::output::status_text;
use crate::bl::display::{print_json, terminal_safe_text};
use crate::bl::skills_api::{exit_codes, failure};
use crate::bl::skills_config::SkillsConfig;
use anyhow::Result;
use blox::proto::WorkstationStatus;
use serde::Serialize;
pub(super) struct LifecycleSummary<'a> {
    pub(super) workstation_id: &'a str,
    pub(super) status: Option<i32>,
    pub(super) success: bool,
    pub(super) message: &'a str,
}

pub(super) fn print_result<T: Serialize>(
    config: &SkillsConfig,
    operation: &str,
    requested_id: &str,
    summary: LifecycleSummary<'_>,
    response: &T,
) -> Result<()> {
    if summary.workstation_id != requested_id {
        return Err(lifecycle_unknown(
            operation,
            requested_id,
            Some(summary.message),
        ));
    }
    if !summary.success
        || matches!(summary.status, Some(status) if status == WorkstationStatus::Error as i32 || status == WorkstationStatus::Degraded as i32)
    {
        return Err(failure(
            exit_codes::GENERAL,
            "lifecycle_failed",
            format!(
                "Blox {operation} failed for workstation {}: {}",
                terminal_safe_text(requested_id),
                if summary.message.is_empty() {
                    "server reported an unsuccessful transition".to_string()
                } else {
                    terminal_safe_text(summary.message)
                }
            ),
        ));
    }
    if let Some(status) = summary.status {
        let accepted = WorkstationStatus::try_from(status).is_ok_and(|status| match operation {
            "suspend" => matches!(
                status,
                WorkstationStatus::Suspending
                    | WorkstationStatus::Suspended
                    | WorkstationStatus::Deleting
                    | WorkstationStatus::Deleted
            ),
            "resume" => matches!(
                status,
                WorkstationStatus::Queued
                    | WorkstationStatus::Creating
                    | WorkstationStatus::Starting
                    | WorkstationStatus::Running
            ),
            _ => false,
        });
        if !accepted {
            return Err(lifecycle_unknown(
                operation,
                requested_id,
                Some(summary.message),
            ));
        }
    }
    if config.json {
        return print_json(response);
    }
    println!("Request accepted: {operation}");
    println!("ID: {}", terminal_safe_text(summary.workstation_id));
    if let Some(status) = summary.status {
        println!("Server status: {}", status_text(status));
    }
    if !summary.message.is_empty() {
        println!("Message: {}", terminal_safe_text(summary.message));
    }
    println!(
        "Inspect progress with `bl blox get {}` (preserve any --base-url override).",
        terminal_safe_text(requested_id)
    );
    Ok(())
}

fn lifecycle_unknown(operation: &str, id: &str, server_message: Option<&str>) -> anyhow::Error {
    let mut message = format!("Blox {operation} result is unknown for workstation {}. Inspect `bl blox get {}` with the same Blox endpoint before trying again; the transition may already be underway. Preserve any --base-url override.", terminal_safe_text(id), terminal_safe_text(id));
    if let Some(server_message) = server_message.filter(|message| !message.is_empty()) {
        message.push_str(&format!(
            " Server message: {}",
            terminal_safe_text(server_message)
        ));
    }
    failure(exit_codes::NETWORK, "lifecycle_outcome_unknown", message)
}

pub(super) fn map_error(error: anyhow::Error, operation: &str, id: &str) -> anyhow::Error {
    if let Some(rpc) = error.downcast_ref::<blox::RpcError>() {
        if !matches!(
            rpc.code.as_str(),
            "unavailable" | "deadline_exceeded" | "unknown" | "internal" | "data_loss"
        ) {
            return map_rpc_error(error);
        }
    }
    lifecycle_unknown(operation, id, None)
}
