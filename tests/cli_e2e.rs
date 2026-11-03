//! End-to-end tests for the sq `agent-tools` binary. The `bl` binary suite
//! lives in `bl_e2e.rs`; shared mock server infrastructure lives in `common/`.

mod common;

use std::fs;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[cfg(unix)]
use common::temp_test_dir;
use common::{
    calculate_tool_schema, list_tools_response, output_text, post_message_tool_schema,
    tool_response, tool_response_with_extension_description, unique_suffix,
    write_extensions_catalog, MockResponse, MockServer, CALL_TOOL_PATH, LIST_EXTENSIONS_PATH,
    LIST_TOOLS_PATH,
};

fn browser_auth_storage_key(profile: &str, server_url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(profile.as_bytes());
    hasher.update([0]);
    hasher.update(server_url.trim_end_matches('/').as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn tool_help_surfaces_schema_derived_flags() {
    let server = MockServer::start(vec![list_tools_response(
        "utils",
        calculate_tool_schema(true),
    )]);

    let output = server
        .command()
        .args(["utils", "calculate", "--help"])
        .output()
        .expect("run agent-tools help");
    let requests = server.finish();
    let (stdout, stderr) = output_text(&output);

    assert!(output.status.success(), "stderr was: {stderr}");
    assert!(stdout.contains("--numbers <NUMBER>"));
    assert!(stdout.contains("--operation <TEXT>"));
    assert!(stdout.contains("--round-up"));
    assert!(stdout.contains("--no-round-up"));
    assert!(stdout.contains("--json <JSON>"));
    assert!(stdout.contains("--raw"));
    assert!(stdout.contains("--header <KEY=VALUE>"));
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, LIST_TOOLS_PATH);
    assert_eq!(requests[0].body["extension_name"], json!("utils"));
}

#[test]
fn tool_help_uses_custom_kgoose_service_path() {
    let server = MockServer::start(vec![list_tools_response(
        "utils",
        calculate_tool_schema(false),
    )]);

    let output = server
        .command()
        .args([
            "--kgoose-service-path",
            "/cash-app/goose-square",
            "utils",
            "calculate",
            "--help",
        ])
        .output()
        .expect("run agent-tools help");
    let requests = server.finish();
    let (_stdout, stderr) = output_text(&output);

    assert!(output.status.success(), "stderr was: {stderr}");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/cash-app/goose-square/v3/list-tools");
}

#[test]
fn tool_help_prints_full_untruncated_description() {
    let long_description = "Look up table metadata to inform downstream queries.\n\n\
        IMPORTANT: Table Meta Data tells you about the structure of a data table, \
        what it is used for, what tables it joins with, who owns it and uses it frequently. \
        Table names are returned in order of search relevance, with the total users recently \
        active and table verification status weighted into the ranking signal so that \
        well-trafficked, human-verified tables surface ahead of stale or unverified ones.\n\n\
        Workflow guidance the agent must follow:\n\
        1. If the table name is unknown, use the user question as search text to find \
        relevant tables that would best answer the analysis question. Enrich the search \
        text with relevant business keywords, brand context, and any known column \
        synonyms so the semantic search can ground its match against the catalog.\n\
        2. If the table name is known - either from the user or the output of \
        query_expert_search - include the table_name argument. The table name MUST be \
        provided in the canonical DATABASE.SCHEMA.TABLE_NAME format. Lowercase input is \
        accepted and will be normalized server-side.\n\
        3. Use the table_owner argument to filter on tables owned by a specific LDAP \
        username such as PAZAR. This is useful for tracing table provenance during \
        on-call investigations or when you need to escalate a verification request.\n\
        4. Read the entire TABLE DESCRIPTION and COLUMN SCHEMA returned to understand \
        what the table contains, how it is partitioned, and which columns are safe to \
        join against without producing fan-out results in your analytics query.\n\n\
        Notes on verification status: VERIFIED tables have been reviewed by a human \
        steward; UNVERIFIED tables may still be useful but should be cross-checked. \
        Brands cover Block, Square, Cash App, Afterpay, Tidal, and Bitkey.\n\
        UNIQUE-MARKER-FOR-FULL-DESCRIPTION-BODY";
    let server = MockServer::start(vec![tool_response(
        "query-expert",
        "find_table_meta_data",
        long_description,
        json!({"type": "object", "properties": {}}).to_string(),
    )]);

    let output = server
        .command()
        .args(["query-expert", "find-table-meta-data", "--help"])
        .output()
        .expect("run tool help");
    let requests = server.finish();
    let (stdout, stderr) = output_text(&output);

    assert!(output.status.success(), "stderr was: {stderr}");
    assert!(
        stdout.contains("UNIQUE-MARKER-FOR-FULL-DESCRIPTION-BODY"),
        "expected full tool description in --help output, got: {stdout}"
    );
    assert!(stdout.contains("Workflow guidance the agent must follow"));
    assert!(stdout.contains("DATABASE.SCHEMA.TABLE_NAME"));
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, LIST_TOOLS_PATH);
}

#[test]
fn extension_help_truncates_long_description_and_advertises_describe() {
    let description = format!(
        "{} {}\n\n{}",
        "Slack tools for chat.",
        "Use this extension to search channels, read threads, and post messages.".repeat(20),
        "This second paragraph should only appear in --describe output."
    );
    let server = MockServer::start(vec![tool_response_with_extension_description(
        "slack",
        &description,
        "search_messages",
        "Search Slack messages",
        json!({
            "type": "object",
            "properties": {}
        })
        .to_string(),
    )]);

    let output = server
        .command()
        .args(["slack", "--help"])
        .output()
        .expect("run extension help");
    let requests = server.finish();
    let (stdout, stderr) = output_text(&output);

    assert!(output.status.success(), "stderr was: {stderr}");
    assert!(stdout.contains("Slack tools for chat."));
    assert!(stdout.contains("describe"));
    assert!(stdout.contains("Print the full extension description/instructions."));
    assert!(stdout.contains("search-messages"));
    assert!(stdout.contains("..."));
    assert!(!stdout.contains("This second paragraph should only appear in --describe output."));
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, LIST_TOOLS_PATH);
    assert_eq!(requests[0].body["extension_name"], json!("slack"));
}

#[test]
fn extension_describe_prints_full_extension_description() {
    let description = "Slack tools for chat.\n\nUse this extension to search channels,\nread threads, and post messages on behalf of the connected account.";
    let server = MockServer::start(vec![tool_response_with_extension_description(
        "slack",
        description,
        "search_messages",
        "Search Slack messages",
        json!({
            "type": "object",
            "properties": {}
        })
        .to_string(),
    )]);

    let output = server
        .command()
        .args(["slack", "describe"])
        .output()
        .expect("run extension describe");
    let requests = server.finish();
    let (stdout, stderr) = output_text(&output);

    assert!(output.status.success(), "stderr was: {stderr}");
    assert_eq!(stdout.trim_end(), description);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, LIST_TOOLS_PATH);
    assert_eq!(requests[0].body["extension_name"], json!("slack"));
}

#[test]
fn write_extensions_accepts_new_list_extensions_auth_fields() {
    let server = MockServer::start(vec![MockResponse::json(json!({
        "extensions": [
            {
                "name": "slack",
                "description": "Slack tools",
                "tool_count": 12,
                "anyToolRequiresUserAuth": true,
                "authSatisfiedForCaller": true
            },
            {
                "name": "airtable",
                "description": "Airtable tools",
                "tool_count": 4,
                "any_tool_requires_user_auth": false,
                "auth_satisfied_for_caller": false
            }
        ]
    }))]);
    let output_path = std::env::temp_dir().join(format!(
        "write-extensions-{}-{}.yaml",
        std::process::id(),
        unique_suffix()
    ));

    let output = server
        .command()
        .arg("--write-extensions")
        .arg(&output_path)
        .output()
        .expect("run write extensions");
    let requests = server.finish();
    let (stdout, stderr) = output_text(&output);
    let catalog = fs::read_to_string(&output_path).expect("read generated catalog");
    fs::remove_file(&output_path).expect("remove generated catalog");

    assert!(output.status.success(), "stderr was: {stderr}");
    assert!(stdout.is_empty(), "stdout was: {stdout}");
    assert!(stderr.is_empty(), "stderr was: {stderr}");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, LIST_EXTENSIONS_PATH);
    assert!(catalog.contains("name: airtable"));
    assert!(catalog.contains("about: Airtable tools"));
    assert!(catalog.contains("name: slack"));
    assert!(catalog.contains("about: Slack tools"));
}

#[test]
fn tool_invocation_posts_expected_payload_and_headers() {
    let server = MockServer::start(vec![
        list_tools_response("utils", calculate_tool_schema(false)),
        MockResponse::json(json!({
            "content": [{"text": {"text": "{\"sum\":5}"}}],
            "is_error": false
        })),
    ]);

    let output = server
        .command()
        .args([
            "--playpen",
            "baxen",
            "--goosemcp-playpen",
            "smohammed",
            "utils",
            "calculate",
            "--numbers",
            "2",
            "3",
            "--operation",
            "add",
            "--header",
            "x-debug=true",
        ])
        .output()
        .expect("run agent-tools tool");
    let requests = server.finish();
    let (stdout, stderr) = output_text(&output);

    assert!(output.status.success(), "stderr was: {stderr}");
    assert_eq!(
        serde_json::from_str::<Value>(stdout.trim()).expect("parse response JSON"),
        json!({"sum": 5})
    );

    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, LIST_TOOLS_PATH);
    assert_eq!(requests[1].path, CALL_TOOL_PATH);
    assert_eq!(
        requests[1].headers.get("baggage").map(String::as_str),
        Some("kgoose-playpen=baxen,envoy-route--goosemcp=playpen-smohammed")
    );
    assert_eq!(
        requests[1].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(requests[1].body["extension_name"], json!("utils"));
    assert_eq!(requests[1].body["tool_name"], json!("calculate"));
    assert_eq!(requests[1].body["headers"]["x-debug"], json!("true"));
    assert_eq!(
        serde_json::from_str::<Value>(
            requests[1].body["arguments_json"]
                .as_str()
                .expect("tool arguments_json"),
        )
        .expect("parse arguments_json"),
        json!({"numbers": [2, 3], "operation": "add"})
    );
}

#[test]
fn tool_invocation_forwards_sts_access_token_as_identity_token() {
    let server = MockServer::start(vec![
        list_tools_response("utils", calculate_tool_schema(false)),
        MockResponse::json(json!({
            "content": [{"text": {"text": "{\"sum\":5}"}}],
            "is_error": false
        })),
    ]);

    let output = server
        .command()
        .env("STS_ACCESS_TOKEN", "test-sidecar-token")
        .args([
            "utils",
            "calculate",
            "--numbers",
            "2",
            "3",
            "--operation",
            "add",
        ])
        .output()
        .expect("run agent-tools tool");
    let requests = server.finish();
    let (_stdout, stderr) = output_text(&output);

    assert!(output.status.success(), "stderr was: {stderr}");
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0]
            .headers
            .get("x-forwarded-identity-token")
            .map(String::as_str),
        Some("test-sidecar-token")
    );
    assert_eq!(
        requests[1]
            .headers
            .get("x-forwarded-identity-token")
            .map(String::as_str),
        Some("test-sidecar-token")
    );
}

#[test]
fn tool_invocation_ignores_bl_auth_storage() {
    let server = MockServer::start(vec![
        list_tools_response("utils", calculate_tool_schema(false)),
        MockResponse::json(json!({
            "content": [{"text": {"text": "{\"sum\":5}"}}],
            "is_error": false
        })),
    ]);
    let temp = std::env::temp_dir().join(format!("sq-kgoose-cli-session-{}", unique_suffix()));
    fs::create_dir_all(&temp).expect("create temp dir");
    let storage_path = temp.join("auth-sessions.json");
    let storage_key =
        browser_auth_storage_key("default", &format!("{}/cash-app/goose", server.base_url));
    fs::write(
        &storage_path,
        serde_json::to_string_pretty(&json!({
            storage_key: {
                "sessionCredential": "stored-kgoose-session",
                "expiresAt": "2026-06-15T00:00:00Z"
            }
        }))
        .expect("serialize storage"),
    )
    .expect("write auth storage");

    let output = server
        .command()
        .env("BL_AUTH_STORAGE", "file")
        .env("BL_AUTH_STORAGE_FILE", &storage_path)
        .args([
            "utils",
            "calculate",
            "--numbers",
            "2",
            "3",
            "--operation",
            "add",
        ])
        .output()
        .expect("run agent-tools tool");
    let requests = server.finish();
    let (_stdout, stderr) = output_text(&output);

    assert!(output.status.success(), "stderr was: {stderr}");
    assert_eq!(requests.len(), 2);
    assert!(!requests[0].headers.contains_key("x-bb-session-credential"));
    assert!(!requests[1].headers.contains_key("x-bb-session-credential"));
    fs::remove_dir_all(temp).expect("remove temp dir");
}

#[test]
fn tool_invocation_prefers_structured_output_over_duplicate_content() {
    let server = MockServer::start(vec![
        list_tools_response("utils", calculate_tool_schema(false)),
        MockResponse::json(json!({
            "content": [
                {"text": {"text": "# Messages\n- hello"}},
                {"structured_content": {"data": {"result": {"messages": [{"text": "hello"}]}}}}
            ],
            "is_error": false,
            "structured_content_json": "{\"result\":{\"messages\":[{\"text\":\"hello\"}]}}"
        })),
    ]);

    let output = server
        .command()
        .args([
            "utils",
            "calculate",
            "--numbers",
            "2",
            "3",
            "--operation",
            "add",
        ])
        .output()
        .expect("run agent-tools tool");
    let _requests = server.finish();
    let (stdout, stderr) = output_text(&output);

    assert!(output.status.success(), "stderr was: {stderr}");
    assert_eq!(
        serde_json::from_str::<Value>(stdout.trim()).expect("parse response JSON"),
        json!({
            "result": {
                "messages": [{"text": "hello"}]
            }
        })
    );
}

#[test]
fn tool_invocation_raw_prints_full_response_envelope() {
    let response = json!({
        "content": [
            {"text": {"text": "{\"sum\":5}"}}
        ],
        "is_error": false,
        "structured_content_json": "{\"sum\":5}"
    });
    let server = MockServer::start(vec![
        list_tools_response("utils", calculate_tool_schema(false)),
        MockResponse::json(response.clone()),
    ]);

    let output = server
        .command()
        .args([
            "utils",
            "calculate",
            "--numbers",
            "2",
            "3",
            "--operation",
            "add",
            "--raw",
        ])
        .output()
        .expect("run agent-tools tool");
    let _requests = server.finish();
    let (stdout, stderr) = output_text(&output);

    assert!(output.status.success(), "stderr was: {stderr}");
    assert_eq!(
        serde_json::from_str::<Value>(stdout.trim()).expect("parse raw response JSON"),
        response
    );
}

#[test]
fn tool_invocation_error_response_exits_nonzero() {
    let server = MockServer::start(vec![
        list_tools_response("utils", calculate_tool_schema(false)),
        MockResponse::json(json!({
            "content": [{"text": {"text": "backend tool failed"}}],
            "is_error": true
        })),
    ]);

    let output = server
        .command()
        .args([
            "utils",
            "calculate",
            "--numbers",
            "2",
            "3",
            "--operation",
            "add",
        ])
        .output()
        .expect("run agent-tools tool");
    let _requests = server.finish();
    let (stdout, stderr) = output_text(&output);

    assert!(!output.status.success());
    assert!(stdout.is_empty(), "stdout was: {stdout}");
    assert!(stderr.contains("backend tool failed"));
}

#[test]
fn optional_boolean_defaults_do_not_crash_invocation() {
    let server = MockServer::start(vec![
        tool_response(
            "slack",
            "post_message",
            "Post a Slack message",
            post_message_tool_schema(),
        ),
        MockResponse::json(json!({
            "content": [{"text": {"text": "{\"ok\":true}"}}],
            "is_error": false
        })),
    ]);

    let output = server
        .command()
        .args(["slack", "post-message", "--channel-id", "C123"])
        .output()
        .expect("run agent-tools tool");
    let requests = server.finish();
    let (stdout, stderr) = output_text(&output);

    assert!(output.status.success(), "stderr was: {stderr}");
    assert_eq!(
        serde_json::from_str::<Value>(stdout.trim()).expect("parse rendered JSON"),
        json!({"ok": true})
    );
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].body["tool_name"], json!("post_message"));
    assert_eq!(
        serde_json::from_str::<Value>(
            requests[1].body["arguments_json"]
                .as_str()
                .expect("tool arguments_json"),
        )
        .expect("parse arguments_json"),
        json!({"channel_id": "C123"})
    );
}

#[cfg(unix)]
#[test]
fn root_metadata_commands_do_not_read_auth_storage() {
    let temp = temp_test_dir("agent-tools-metadata-auth-storage");
    let malformed_storage = temp.join("auth-sessions.json");
    fs::write(&malformed_storage, "not json").expect("write malformed auth storage");

    for args in [
        vec!["--version"],
        vec!["--summary"],
        vec!["--describe-commands"],
    ] {
        let server = MockServer::start(vec![]);
        let output = server
            .command()
            .env("BL_AUTH_STORAGE", "file")
            .env("BL_AUTH_STORAGE_FILE", &malformed_storage)
            .args(args)
            .output()
            .expect("run metadata command");
        let requests = server.finish();
        let (_stdout, stderr) = output_text(&output);

        assert!(output.status.success(), "stderr was: {stderr}");
        assert!(requests.is_empty(), "requests were: {requests:#?}");
    }

    fs::remove_dir_all(temp).expect("remove temp dir");
}

#[test]
fn describe_commands_uses_static_catalog_without_network() {
    let server = MockServer::start(vec![]);
    let catalog_path = write_extensions_catalog(
        "describe-commands",
        r#"
- name: secret
  about: Needs more auth
- name: utils
  about: Utility helpers
"#,
    );

    let output = server
        .command()
        .env("KGOOSE_EXTENSIONS_CATALOG", &catalog_path)
        .arg("--describe-commands")
        .output()
        .expect("run describe-commands");
    let requests = server.finish();
    let (stdout, stderr) = output_text(&output);
    fs::remove_file(&catalog_path).expect("remove extensions catalog");

    assert!(output.status.success(), "stderr was: {stderr}");
    let description = serde_json::from_str::<Value>(&stdout).expect("parse describe output");
    assert_eq!(description["name"], json!("agent-tools"));
    let expected_commands = json!([
        {
            "name": "secret",
            "summary": "Needs more auth"
        },
        {
            "name": "utils",
            "summary": "Utility helpers"
        }
    ]);
    assert_eq!(description["commands"], expected_commands);
    assert!(stderr.is_empty(), "stderr was: {stderr}");
    assert!(requests.is_empty(), "requests were: {requests:#?}");
}

#[test]
fn inaccessible_extension_errors_are_humanized_in_e2e_flow() {
    let server = MockServer::start(vec![MockResponse::text(
        404,
        "Extension 'notion' not found or not authorized",
    )]);

    let output = server
        .command()
        .args(["--playpen", "baxen", "notion", "--help"])
        .output()
        .expect("run help for inaccessible extension");
    let requests = server.finish();
    let (_stdout, stderr) = output_text(&output);

    assert!(!output.status.success());
    assert!(stderr.contains("Can't inspect `notion` in playpen `baxen`"));
    assert!(stderr.contains("wouldn't return its tools"));
    assert!(stderr.contains("G2 Connections settings"));
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, LIST_TOOLS_PATH);
}

fn blox_agent_tools_command(tools_base_url: Option<&str>) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_agent-tools"));
    for name in [
        "KGOOSE_BASE_URL",
        "KGOOSE_DEBUG",
        "KGOOSE_PLAYPEN",
        "KGOOSE_SERVICE_PATH",
        "KGOOSE_TIMEOUT",
        "BL_TOOLS_BASE_URL",
    ] {
        command.env_remove(name);
    }
    command
        .env("IS_BLOX", "true")
        .env("BLOX_WORKSTATION_ID", "agent-tools-test-workstation")
        .env("BLOX_ENVIRONMENT", "production")
        .env("STS_ACCESS_TOKEN", "internal-sts-token");
    if let Some(base_url) = tools_base_url {
        command.env("BL_TOOLS_BASE_URL", base_url);
    }
    command
}

#[test]
fn agent_tools_blox_proxy_defaults_to_tools_base_url_without_identity_token() {
    let server = MockServer::start(vec![
        list_tools_response("utils", calculate_tool_schema(false)),
        MockResponse::json(json!({
            "content": [{"text": {"text": "{\"sum\":5}"}}],
            "is_error": false
        })),
    ]);
    let catalog_path = write_extensions_catalog(
        "blox-proxy",
        r#"
- name: utils
  about: Utility helpers
"#,
    );

    let help = blox_agent_tools_command(Some(&server.base_url))
        .env("KGOOSE_EXTENSIONS_CATALOG", &catalog_path)
        .arg("--help")
        .output()
        .expect("run root help");
    let output = blox_agent_tools_command(Some(&server.base_url))
        .args([
            "utils",
            "calculate",
            "--numbers",
            "2",
            "3",
            "--operation",
            "add",
        ])
        .output()
        .expect("run proxied tool");
    let requests = server.finish();
    fs::remove_file(&catalog_path).expect("remove extensions catalog");
    let (help_stdout, help_stderr) = output_text(&help);
    let (stdout, stderr) = output_text(&output);

    assert!(help.status.success(), "stderr was: {help_stderr}");
    assert!(help_stdout.contains("Utility helpers"));
    assert!(output.status.success(), "stderr was: {stderr}");
    assert!(stdout.contains("sum"), "stdout was: {stdout}");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, LIST_TOOLS_PATH);
    assert_eq!(requests[1].path, CALL_TOOL_PATH);
    for request in &requests {
        for header in [
            "authorization",
            "cookie",
            "x-bb-session-credential",
            "x-forwarded-identity-token",
        ] {
            assert!(!request.headers.contains_key(header), "unexpected {header}");
        }
    }
}

#[test]
fn agent_tools_blox_keeps_identity_token_without_the_full_proxy_gate() {
    let server = MockServer::start(
        (0..5)
            .map(|_| list_tools_response("utils", calculate_tool_schema(false)))
            .collect(),
    );
    let mut commands = Vec::new();
    commands.push(blox_agent_tools_command(None));
    commands.push(blox_agent_tools_command(Some("http://other.example.test")));
    let mut not_blox = blox_agent_tools_command(Some(&server.base_url));
    not_blox.env("IS_BLOX", "false");
    commands.push(not_blox);
    let mut no_workstation = blox_agent_tools_command(Some(&server.base_url));
    no_workstation.env_remove("BLOX_WORKSTATION_ID");
    commands.push(no_workstation);
    let mut empty_workstation = blox_agent_tools_command(Some(&server.base_url));
    empty_workstation.env("BLOX_WORKSTATION_ID", "");
    commands.push(empty_workstation);

    for mut command in commands {
        let output = command
            .args(["--base-url", &server.base_url, "utils", "--help"])
            .output()
            .expect("run agent-tools without the proxy gate");
        let (_, stderr) = output_text(&output);
        assert!(output.status.success(), "stderr was: {stderr}");
    }
    let requests = server.finish();

    assert_eq!(requests.len(), 5);
    for request in &requests {
        assert_eq!(request.path, LIST_TOOLS_PATH);
        assert_eq!(
            request
                .headers
                .get("x-forwarded-identity-token")
                .map(String::as_str),
            Some("internal-sts-token")
        );
    }
}

#[test]
fn agent_tools_blox_proxy_points_inaccessible_extensions_at_builderlab_connections() {
    let server = MockServer::start(vec![MockResponse::text(
        403,
        "Extension 'notion' not authorized",
    )]);

    let output = blox_agent_tools_command(Some(&server.base_url))
        .args(["notion", "--help"])
        .output()
        .expect("run help for inaccessible extension");
    let requests = server.finish();
    let (_, stderr) = output_text(&output);

    assert!(!output.status.success());
    assert!(
        stderr.contains("Can't inspect `notion`"),
        "stderr was: {stderr}"
    );
    assert!(stderr.contains("Connections page of your BuilderLab portal"));
    assert!(!stderr.contains("g2.sqprod.co"));
    assert_eq!(requests.len(), 1);
}
