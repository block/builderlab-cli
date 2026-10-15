use super::context;
use super::context::map_error;
use crate::bl::display::{print_json, terminal_safe_text};
use crate::bl::skills_config::SkillsConfig;
use anyhow::Result;
use clap::{ArgMatches, Command};

pub(super) fn command() -> Command {
    Command::new("skus").about("List available workstation SKUs and maximum multiples")
}

pub(super) fn run(config: &SkillsConfig, args: &ArgMatches) -> Result<()> {
    let client = context::client(config, args, "skus")?;
    let response = client.list_compute_providers().map_err(map_error)?;
    if config.json {
        print_json(&response)
    } else {
        if response.compute_skus.is_empty() {
            println!("No workstation SKUs are available for your account.");
        } else {
            println!("CODE\tNAME\tMAX MULTIPLE\tPROVIDER");
            for sku in &response.compute_skus {
                println!(
                    "{}\t{}\t{}\t{}",
                    terminal_safe_text(&sku.code),
                    terminal_safe_text(&sku.display_name),
                    sku.max_multiple,
                    terminal_safe_text(&sku.compute_provider)
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use serde_json::json;

    #[test]
    fn skus_discovery_preserves_catalog_json_and_prints_codes_with_maximums() {
        for json_output in [false, true] {
            let auth = auth_service();
            let catalog = json!({"computeSkuRequired":true, "computeSkus":[{"code":"DEFAULT_AMD64", "displayName":"Default", "cpu":1, "memoryGb":8, "maxMultiple":8, "computeProvider":"worker-cells"}]});
            let service = MockService::start(200, catalog.clone());
            let mut args = vec![
                "compute",
                "skus",
                "--base-url",
                "https://blox.test.blockstaging.build",
            ];
            if json_output {
                args.push("--json");
            }
            let output = run_process(&auth, &service, &args);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            if json_output {
                assert_eq!(output_json(&output), catalog);
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(stdout.contains("MAX MULTIPLE"));
                assert!(stdout.contains("DEFAULT_AMD64\tDefault\t8\tworker-cells"));
            }
            let (path, request) = assert_shared_auth(auth, service);
            assert!(path.ends_with(".OrchestratorService/ListComputeProviders"));
            assert_eq!(request, json!({}));
        }
    }
}
