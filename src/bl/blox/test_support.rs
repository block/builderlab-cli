//! Isolated subprocess and mock-service support for Blox command tests.

use std::collections::BTreeMap;
use std::process::{Command as ProcessCommand, Output};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tiny_http::{Header, Response, Server};

// Runs the CLI in its own process so environment-based auth is isolated
// from other unit tests and uses the real stored-session verification.
#[test]
fn blox_process_helper() {
    let Ok(argv) = std::env::var("BL_BLOX_E2E_ARGS") else {
        return;
    };
    println!("BLOX_E2E_OUTPUT_BEGIN");
    let result = crate::run_bl_with_argv(serde_json::from_str(&argv).unwrap());
    if let Err(error) = result {
        if let Some(silent) = error.downcast_ref::<crate::bl::skills_api::SilentJsonExit>() {
            std::process::exit(silent.0);
        }
        eprintln!("error: {error:#}");
        std::process::exit(crate::bl::skills_api::failure_info(&error).0);
    }
    println!("BLOX_E2E_OUTPUT_END");
}

pub(super) type RecordedRequest = (String, BTreeMap<String, String>, Value);

pub(super) enum MockReply {
    Json(u16, Value),
    Stream(Vec<Value>, Value),
}

pub(super) struct MockService {
    pub(super) url: String,
    request: thread::JoinHandle<Vec<RecordedRequest>>,
}

impl MockService {
    pub(super) fn start(status: u16, value: Value) -> Self {
        Self::steps(vec![MockReply::Json(status, value)])
    }

    pub(super) fn steps(replies: Vec<MockReply>) -> Self {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr());
        let request = thread::spawn(move || {
            let mut requests = Vec::new();
            for reply in replies {
                let mut request = server
                    .recv_timeout(Duration::from_secs(15))
                    .unwrap()
                    .expect("mock request");
                let path = request.url().to_string();
                let headers = request
                    .headers()
                    .iter()
                    .map(|header| {
                        (
                            header.field.to_string().to_ascii_lowercase(),
                            header.value.to_string(),
                        )
                    })
                    .collect();
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).unwrap();
                let body = if body.is_empty() {
                    Value::Null
                } else if body[0] == 0 {
                    // Server-streaming Connect requests carry one framed JSON message.
                    serde_json::from_slice(&body[5..]).unwrap()
                } else {
                    serde_json::from_slice(&body).unwrap()
                };
                let (status, bytes, content_type) = match reply {
                    MockReply::Json(status, value) => (
                        status,
                        serde_json::to_vec(&value).unwrap(),
                        "application/json",
                    ),
                    MockReply::Stream(outputs, terminal) => {
                        let mut bytes = Vec::new();
                        for (flags, value) in outputs
                            .into_iter()
                            .map(|output| (0, output))
                            .chain(std::iter::once((2, terminal)))
                        {
                            let body = serde_json::to_vec(&value).unwrap();
                            bytes.push(flags);
                            bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
                            bytes.extend_from_slice(&body);
                        }
                        (200, bytes, "application/connect+json")
                    }
                };
                request
                    .respond(
                        Response::from_data(bytes)
                            .with_status_code(status)
                            .with_header(Header::from_bytes("Content-Type", content_type).unwrap()),
                    )
                    .unwrap();
                requests.push((path, headers, body));
            }
            requests
        });
        Self { url, request }
    }

    pub(super) fn finish(self) -> RecordedRequest {
        let mut requests = self.finish_all();
        assert_eq!(requests.len(), 1);
        requests.pop().unwrap()
    }

    pub(super) fn finish_all(self) -> Vec<RecordedRequest> {
        self.request.join().unwrap()
    }
}

pub(super) fn run_process(auth: &MockService, service: &MockService, args: &[&str]) -> Output {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.yaml"), "org: test\n").unwrap();
    let session_path = home.path().join("sessions.json");
    let service_url = format!("{}/api/goose", auth.url);
    let mut hash = Sha256::new();
    hash.update(b"default");
    hash.update([0]);
    hash.update(service_url.as_bytes());
    let key = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    std::fs::write(&session_path, json!({ key: {"sessionCredential":"blox-test-only.session", "expiresAt":"2099-01-01T00:00:00Z"}}).to_string()).unwrap();
    let argv = std::iter::once("bl")
        .chain(args.iter().copied())
        .map(str::to_string)
        .collect::<Vec<_>>();
    ProcessCommand::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "bl::blox::test_support::blox_process_helper",
            "--nocapture",
        ])
        .env("BL_BLOX_E2E_ARGS", serde_json::to_string(&argv).unwrap())
        .env("BL_BLOX_E2E_ENDPOINT", &service.url)
        .env("BL_HOME", home.path())
        .env("BL_AUTH_STORAGE", "file")
        .env("BL_AUTH_STORAGE_FILE", session_path)
        .env("KGOOSE_BASE_URL", &auth.url)
        .env("KGOOSE_SERVICE_PATH", "/api/goose")
        .env_remove("BL_SKILLS_CONFIG")
        .env_remove("BL_SKILLS_PROFILE")
        .env_remove("BL_KGOOSE_PLAYPEN")
        .env_remove("KGOOSE_PLAYPEN")
        .env_remove("BL_BLOX_CONTROL_PLANE_URL")
        .output()
        .unwrap()
}

pub(super) fn auth_service() -> MockService {
    MockService::start(
        200,
        json!({"subject":"test", "email":"blox-test@example.test", "name":"Test", "expires_at":"2099-01-01T00:00:00Z", "workspaces":{"active":[]}}),
    )
}

pub(super) fn assert_shared_auth(auth: MockService, service: MockService) -> (String, Value) {
    let (auth_path, auth_headers, _) = auth.finish();
    assert_eq!(auth_path, "/api/goose/v1/auth/me");
    assert_eq!(
        auth_headers["x-bb-session-credential"],
        "blox-test-only.session"
    );
    let (path, headers, body) = service.finish();
    assert_eq!(
        headers["authorization"],
        "BBIdentity blox-test-only.session"
    );
    for header in [
        "cookie",
        "x-bb-session-credential",
        "x-forwarded-identity-token",
        "x-forwarded-user",
        "x-blox-workstation-key",
    ] {
        assert!(!headers.contains_key(header), "unexpected {header}");
    }
    (path, body)
}

pub(super) fn output_json(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let body = stdout
        .split("BLOX_E2E_OUTPUT_BEGIN")
        .nth(1)
        .unwrap()
        .split("BLOX_E2E_OUTPUT_END")
        .next()
        .unwrap();
    serde_json::from_str(body.trim()).unwrap()
}

pub(super) fn process_stdout(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let body = stdout.split("BLOX_E2E_OUTPUT_BEGIN\n").nth(1).unwrap();
    body.split("BLOX_E2E_OUTPUT_END")
        .next()
        .unwrap()
        .to_string()
}

pub(super) fn lifecycle_service(target: &str, status: u16, response: Value) -> MockService {
    MockService::steps(vec![
        MockReply::Json(
            200,
            json!({"workstation":{"workstationId":target, "name":"123", "status":"WORKSTATION_STATUS_DELETED"}}),
        ),
        MockReply::Json(status, response),
    ])
}

pub(super) fn assert_lifecycle_requests(
    auth: MockService,
    service: MockService,
    operation: &str,
    target: &str,
) {
    assert_eq!(auth.finish().0, "/api/goose/v1/auth/me");
    let requests = service.finish_all();
    assert_eq!(requests.len(), 2);
    assert!(requests[0]
        .0
        .ends_with(".OrchestratorService/GetWorkstation"));
    let rpc = match operation {
        "suspend" => "SuspendWorkstation",
        "resume" => "ResumeWorkstation",
        "delete" => "DeleteWorkstation",
        _ => panic!("unknown test operation"),
    };
    assert!(requests[1]
        .0
        .ends_with(&format!(".OrchestratorService/{rpc}")));
    assert_eq!(requests[1].2, json!({"workstationId":target}));
    for (_, headers, _) in requests {
        assert_eq!(
            headers["authorization"],
            "BBIdentity blox-test-only.session"
        );
        assert!(!headers.contains_key("x-forwarded-identity-token"));
        assert!(!headers.contains_key("cookie"));
    }
}
