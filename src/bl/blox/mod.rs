//! Blox workstation commands using the shared BuilderLab session.
mod context;
mod create;
mod delete;
mod exec;
mod get;
mod lifecycle;
mod list;
mod output;
mod resume;
mod skus;
mod suspend;
#[cfg(test)]
mod test_support;

use crate::bl::runner;
use crate::bl::skills_config::SkillsConfig;
use anyhow::{Context, Result};
use clap::{ArgMatches, Command};
use serde_json::Value;

pub fn command() -> Command {
    context::args(Command::new("compute")
        .alias("blox")
        .about("Manage Blox workstations")
        .long_about("Manage your Blox workstations using your BuilderLab login. Names are resolved by the orchestrator; use the full ID to identify an archived workstation.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .disable_help_subcommand(true)
        .subcommand(list::command())
        .subcommand(skus::command())
        .subcommand(create::command())
        .subcommand(exec::command())
        .subcommand(suspend::command())
        .subcommand(resume::command())
        .subcommand(delete::command())
        .subcommand(get::command()))
}

pub fn describe_commands() -> Value {
    crate::bl::description::describe_command_tree(&command())
}

pub fn run(matches: &ArgMatches) -> Result<()> {
    runner::run(matches, dispatch)
}

fn dispatch(config: &SkillsConfig, matches: &ArgMatches) -> Result<()> {
    let (operation, args) = matches
        .subcommand()
        .context("expected a compute subcommand")?;
    match operation {
        "list" => list::run(config, args),
        "get" => get::run(config, args),
        "skus" => skus::run(config, args),
        "create" => create::run(config, args),
        "exec" => exec::run(config, args),
        "suspend" => suspend::run(config, args),
        "resume" => resume::run(config, args),
        "delete" => delete::run(config, args),
        _ => anyhow::bail!("expected a compute subcommand"),
    }
}
