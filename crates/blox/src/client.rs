use std::fmt;
use std::io::Read;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::blocking::Client as HttpClient;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use crate::proto::{
    DeleteWorkstationRequest, DeleteWorkstationResponse, ExecuteProcessRequest,
    ExecuteProcessResponse, GetWorkstationRequest, GetWorkstationResponse,
    ListComputeProvidersRequest, ListComputeProvidersResponse, ListWorkstationsRequest,
    ListWorkstationsResponse, ResumeWorkstationRequest, ResumeWorkstationResponse,
    StartWorkstationRequest, StartWorkstationResponse, StreamCommandOutputRequest,
    StreamCommandOutputResponse, SuspendWorkstationRequest, SuspendWorkstationResponse,
};

const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

const SERVICE: &str = "xyz.block.blox.orchestrator.v1.OrchestratorService";

/// An orchestrator Connect unary client. Credentials are supplied by the caller.
pub struct Client {
    base_url: Url,
    http: HttpClient,
    streaming_http: HttpClient,
    headers: HeaderMap,
}

/// A Connect RPC error, retaining the server's machine-readable code.
#[derive(Debug, Deserialize)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

impl fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

#[derive(Deserialize)]
struct EndStream {
    #[serde(default)]
    error: Option<RpcError>,
}

impl Client {
    /// Use an existing BuilderLab session at an ingress that accepts BBIdentity.
    pub fn with_session_credential(mut self, credential: &str) -> Result<Self> {
        anyhow::ensure!(
            !credential.is_empty(),
            "BuilderLab session credential must not be empty"
        );
        let mut value = HeaderValue::from_str(&format!("BBIdentity {credential}"))
            .context("invalid BuilderLab session credential")?;
        value.set_sensitive(true);
        self.headers.insert("authorization", value);
        Ok(self)
    }

    /// Build a client for an explicit HTTP(S) orchestrator endpoint.
    pub fn new(base_url: &str) -> Result<Self> {
        let mut base_url = Url::parse(base_url).context("parse Blox orchestrator URL")?;
        anyhow::ensure!(
            matches!(base_url.scheme(), "http" | "https")
                && base_url.host_str().is_some()
                && base_url.username().is_empty()
                && base_url.password().is_none()
                && base_url.query().is_none()
                && base_url.fragment().is_none(),
            "Blox orchestrator URL must be an HTTP(S) URL without credentials, query, or fragment"
        );
        let prefix = format!("{}/", base_url.path().trim_end_matches('/'));
        base_url.set_path(&prefix);

        let mut headers = HeaderMap::new();
        headers.insert("connect-protocol-version", HeaderValue::from_static("1"));
        let http = HttpClient::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .context("build Blox HTTP client")?;
        let streaming_http = HttpClient::builder()
            .timeout(None)
            .connect_timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .context("build Blox streaming HTTP client")?;
        Ok(Self {
            base_url,
            http,
            streaming_http,
            headers,
        })
    }

    /// List the caller's workstations using the supplied filters.
    pub fn list_workstations(
        &self,
        request: &ListWorkstationsRequest,
    ) -> Result<ListWorkstationsResponse> {
        self.call("ListWorkstations", request)
    }

    /// Retrieve a workstation by its ID or name.
    pub fn get_workstation(&self, id_or_name: &str) -> Result<GetWorkstationResponse> {
        self.call(
            "GetWorkstation",
            &GetWorkstationRequest {
                workstation: id_or_name.to_owned(),
            },
        )
    }

    /// Create a workstation once, without retrying an ambiguous result.
    pub fn start_workstation(
        &self,
        request: &StartWorkstationRequest,
    ) -> Result<StartWorkstationResponse> {
        self.call("StartWorkstation", request)
    }

    /// Discover compute SKUs available to the caller.
    pub fn list_compute_providers(&self) -> Result<ListComputeProvidersResponse> {
        self.call("ListComputeProviders", &ListComputeProvidersRequest {})
    }

    /// Launch one durable process. An ambiguous result must never be retried.
    pub fn execute_process(
        &self,
        request: &ExecuteProcessRequest,
    ) -> Result<ExecuteProcessResponse> {
        self.call("ExecuteProcess", request)
    }

    /// Request suspension once, returning the current lifecycle status.
    pub fn suspend_workstation(
        &self,
        request: &SuspendWorkstationRequest,
    ) -> Result<SuspendWorkstationResponse> {
        self.call_with_timeout("SuspendWorkstation", request, Duration::from_secs(12 * 60))
    }

    /// Request resumption once, returning the current lifecycle status.
    pub fn resume_workstation(
        &self,
        request: &ResumeWorkstationRequest,
    ) -> Result<ResumeWorkstationResponse> {
        self.call_with_timeout("ResumeWorkstation", request, Duration::from_secs(12 * 60))
    }

    /// Request deletion once. The caller must inspect the response's success.
    pub fn delete_workstation(
        &self,
        request: &DeleteWorkstationRequest,
    ) -> Result<DeleteWorkstationResponse> {
        self.call_with_timeout("DeleteWorkstation", request, Duration::from_secs(12 * 60))
    }

    /// Follow output with bounded Connect envelopes and no overall time limit.
    ///
    /// Returns only after the protocol's end-stream envelope. A callback error
    /// stops reading without stopping or restarting the remote process.
    pub fn stream_command_output(
        &self,
        request: &StreamCommandOutputRequest,
        mut on_output: impl FnMut(StreamCommandOutputResponse) -> Result<()>,
    ) -> Result<()> {
        let payload = serde_json::to_vec(request)?;
        let mut envelope = Vec::with_capacity(payload.len() + 5);
        envelope.push(0);
        envelope.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
        envelope.extend_from_slice(&payload);
        let url = self
            .base_url
            .join(&format!("{SERVICE}/StreamCommandOutput"))?;
        let response = self
            .streaming_http
            .post(url)
            .headers(self.headers.clone())
            .header("content-type", "application/connect+json")
            .header("accept-encoding", "identity")
            .header("connect-accept-encoding", "identity")
            .body(envelope)
            .send()
            .context("call Blox StreamCommandOutput")?;
        let status = response.status();
        let response_headers = response.headers().clone();
        if !status.is_success() {
            let mut body = Vec::new();
            response
                .take(MAX_RESPONSE_BYTES + 1)
                .read_to_end(&mut body)
                .context("read Blox StreamCommandOutput error")?;
            anyhow::ensure!(
                body.len() as u64 <= MAX_RESPONSE_BYTES,
                "Blox StreamCommandOutput error exceeds 2 MiB"
            );
            return Err(self.response_error(
                status,
                &body,
                "StreamCommandOutput",
                &response_headers,
            ));
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        anyhow::ensure!(
            content_type.split(';').next().is_some_and(|value| value
                .trim()
                .eq_ignore_ascii_case("application/connect+json")),
            "Blox StreamCommandOutput returned an invalid content type"
        );
        for header in ["content-encoding", "connect-content-encoding"] {
            anyhow::ensure!(
                response
                    .headers()
                    .get(header)
                    .is_none_or(|value| value == "identity"),
                "Blox StreamCommandOutput returned unsupported compression"
            );
        }
        self.read_output_stream(response, &mut on_output)
    }

    fn read_output_stream(
        &self,
        mut reader: impl Read,
        on_output: &mut impl FnMut(StreamCommandOutputResponse) -> Result<()>,
    ) -> Result<()> {
        loop {
            let mut header = [0; 5];
            reader
                .read_exact(&mut header)
                .context("Blox output stream ended before its end-stream envelope")?;
            anyhow::ensure!(
                header[0] == 0 || header[0] == 2,
                "Blox output stream has unsupported envelope flags"
            );
            let length = u32::from_be_bytes(header[1..].try_into()?) as u64;
            anyhow::ensure!(
                length <= MAX_RESPONSE_BYTES,
                "Blox output envelope exceeds 2 MiB"
            );
            let mut payload = vec![0; length as usize];
            reader
                .read_exact(&mut payload)
                .context("Blox output envelope is truncated")?;
            if header[0] == 2 {
                let end: EndStream =
                    self.decode_response(&payload, "StreamCommandOutput end-stream")?;
                if let Some(error) = end.error {
                    return Err(error.into());
                }
                return Ok(());
            }
            let output: StreamCommandOutputResponse =
                self.decode_response(&payload, "StreamCommandOutput")?;
            let data = String::from_utf8_lossy(&output.data);
            anyhow::ensure!(
                self.redact(&data) == data,
                "Blox output contains reflected authentication credentials"
            );
            on_output(output)?;
        }
    }

    fn call<T: Serialize, R: DeserializeOwned>(&self, method: &str, request: &T) -> Result<R> {
        self.call_with_timeout(method, request, Duration::from_secs(30))
    }

    fn call_with_timeout<T: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        request: &T,
        timeout: Duration,
    ) -> Result<R> {
        let url = self.base_url.join(&format!("{SERVICE}/{method}"))?;
        let response = self
            .http
            .post(url)
            .headers(self.headers.clone())
            .json(request)
            .timeout(timeout)
            .send()
            .with_context(|| format!("call Blox {method}"))?;
        let status = response.status();
        let response_headers = response.headers().clone();
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .with_context(|| format!("read Blox {method} response"))?;
        anyhow::ensure!(
            body.len() as u64 <= MAX_RESPONSE_BYTES,
            "Blox {method} response exceeds 2 MiB"
        );
        if !status.is_success() {
            return Err(self.response_error(status, &body, method, &response_headers));
        }
        self.decode_response(&body, method)
    }

    fn response_error(
        &self,
        status: reqwest::StatusCode,
        body: &[u8],
        method: &str,
        headers: &HeaderMap,
    ) -> anyhow::Error {
        let context = self.response_error_context(headers);
        if let Ok(mut error) = serde_json::from_slice::<RpcError>(body) {
            error.code = strip_bidi_controls(&strip_ansi(&self.redact(&error.code)))
                .chars()
                .filter(|character| !character.is_control())
                .collect();
            error.message = format!(
                "Blox {method} failed with HTTP {status}: {}{}",
                self.sanitize_detail(&error.message),
                context
            );
            return error.into();
        }
        let code = match status.as_u16() {
            401 => "unauthenticated",
            403 => "permission_denied",
            404 => "not_found",
            408 | 504 => "deadline_exceeded",
            429 => "resource_exhausted",
            502 | 503 => "unavailable",
            _ => "unknown",
        };
        RpcError {
            code: code.to_owned(),
            message: format!(
                "Blox {method} failed with HTTP {status}{}{}",
                context,
                self.response_body_detail(body, headers)
                    .map(|detail| format!(" (detail={detail})"))
                    .unwrap_or_default()
            ),
        }
        .into()
    }

    fn response_error_context(&self, headers: &HeaderMap) -> String {
        let mut details = Vec::new();
        for name in ["x-request-id", "x-correlation-id"] {
            if let Some(value) = headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 96
                        && self.redact(value) == *value
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
                })
            {
                details.push(format!("{name}={value}"));
                break;
            }
        }
        if let Some(value) = headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .filter(|value| {
                value.len() <= 128
                    && self.redact(value) == *value
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"/;=+.- _".contains(&byte))
            })
        {
            details.push(format!("content-type={value}"));
        }
        if details.is_empty() {
            String::new()
        } else {
            format!(" ({})", details.join(", "))
        }
    }

    fn response_body_detail(&self, body: &[u8], headers: &HeaderMap) -> Option<String> {
        if body.is_empty() {
            return None;
        }
        let content_type = headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()?
            .trim()
            .to_ascii_lowercase();
        let text = if content_type == "application/json"
            || content_type.ends_with("+json")
            || content_type == "application/connect+json"
        {
            let value: serde_json::Value = serde_json::from_slice(body).ok()?;
            value
                .get("message")
                .or_else(|| value.get("detail"))
                .or_else(|| value.get("error"))?
                .as_str()?
                .to_owned()
        } else {
            return None;
        };
        let detail = self.sanitize_detail(&text);
        (!detail.is_empty()).then_some(detail)
    }

    fn sanitize_detail(&self, value: &str) -> String {
        let value = strip_bidi_controls(&strip_ansi(value));
        // Drop controls before classification so they cannot split a sensitive marker.
        let value: String = value
            .chars()
            .filter(|character| !character.is_control())
            .collect();
        let value = self.redact(&value);
        if contains_sensitive_marker(&value) || contains_url(&value) {
            return "[response detail omitted: may contain sensitive data]".to_owned();
        }
        let mut safe = String::with_capacity(value.len().min(256));
        let mut pending_space = false;
        for character in value.chars() {
            if character.is_control() || character.is_whitespace() {
                pending_space = !safe.is_empty();
                continue;
            }
            if pending_space {
                safe.push(' ');
                pending_space = false;
            }
            if safe.len() + character.len_utf8() > 240 {
                safe.push('…');
                break;
            }
            safe.push(character);
        }
        safe
    }

    fn decode_response<R: DeserializeOwned>(&self, body: &[u8], method: &str) -> Result<R> {
        let value: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
            anyhow::anyhow!(
                "decode Blox {method} response: {}",
                self.redact(&error.to_string())
            )
        })?;
        // Reflected credentials must never reach typed fields or caller output.
        anyhow::ensure!(
            !self.contains_credential(&value),
            "Blox {method} response contains reflected authentication credentials"
        );
        serde_json::from_value(value).map_err(|error| {
            anyhow::anyhow!(
                "decode Blox {method} response: {}",
                self.redact(&error.to_string())
            )
        })
    }

    fn redact(&self, message: &str) -> String {
        let Some(value) = self
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
        else {
            return message.to_owned();
        };
        let mut redacted = message.replace(value, "[REDACTED]");
        if let Some(credential) = value.strip_prefix("BBIdentity ") {
            redacted = redacted.replace(credential, "[REDACTED]");
        }
        redacted
    }

    fn contains_credential(&self, value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(value) => self.redact(value) != *value,
            serde_json::Value::Array(values) => {
                values.iter().any(|value| self.contains_credential(value))
            }
            serde_json::Value::Object(values) => values
                .iter()
                .any(|(key, value)| self.redact(key) != *key || self.contains_credential(value)),
            _ => false,
        }
    }
}

fn contains_sensitive_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "authorization",
        "cookie",
        "token",
        "password",
        "secret",
        "api_key",
        "api-key",
        "apikey",
        "accesstoken",
        "refreshtoken",
        "client_secret",
        "clientsecret",
        "credential",
        "session",
        "passwd",
        "bearer ",
        "set-cookie",
        "bbidentity ",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn contains_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("://") || lower.contains('?')
}

fn strip_bidi_controls(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            !matches!(
                *character as u32,
                0x00ad
                    | 0x061c
                    | 0x200b..=0x200f
                    | 0x202a..=0x202e
                    | 0x2060..=0x206f
                    | 0xfeff
            )
        })
        .collect()
}

fn strip_ansi(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\u{1b}' {
            safe.push(character);
            continue;
        }
        match characters.next() {
            Some('[') => {
                for character in characters.by_ref() {
                    if ('@'..='~').contains(&character) {
                        break;
                    }
                }
            }
            Some(']') => {
                let mut previous_escape = false;
                for character in characters.by_ref() {
                    if character == '\u{7}' || (previous_escape && character == '\\') {
                        break;
                    }
                    previous_escape = character == '\u{1b}';
                }
            }
            Some(_) => {}
            None => {}
        }
    }
    safe
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use tiny_http::{Header, Response, Server};

    fn frame(flags: u8, payload: &str) -> Vec<u8> {
        let mut bytes = vec![flags];
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload.as_bytes());
        bytes
    }

    #[test]
    fn lifecycle_calls_preserve_typed_results_and_use_one_canonical_id() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let client = Client::new(&format!("http://{}", server.server_addr()))
            .unwrap()
            .with_session_credential("session")
            .unwrap();
        let worker = thread::spawn(move || {
            for (method, response) in [
                (
                    "SuspendWorkstation",
                    r#"{"workstationId":"ws-1","status":"WORKSTATION_STATUS_SUSPENDING","message":"draining"}"#,
                ),
                (
                    "ResumeWorkstation",
                    r#"{"workstationId":"ws-1","status":"WORKSTATION_STATUS_ERROR","message":"resume failed"}"#,
                ),
                (
                    "DeleteWorkstation",
                    r#"{"workstationId":"ws-1","success":false,"message":"deletion denied"}"#,
                ),
            ] {
                let mut request = server.recv().unwrap();
                assert_eq!(request.method().as_str(), "POST");
                assert_eq!(request.url(), format!("/{SERVICE}/{method}"));
                assert_eq!(
                    request
                        .headers()
                        .iter()
                        .find(|h| h.field.equiv("Authorization"))
                        .unwrap()
                        .value
                        .as_str(),
                    "BBIdentity session"
                );
                let mut body = String::new();
                request.as_reader().read_to_string(&mut body).unwrap();
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                    serde_json::json!({"workstationId":"ws-1"})
                );
                request.respond(Response::from_string(response)).unwrap();
            }
        });
        let response = client
            .suspend_workstation(&SuspendWorkstationRequest {
                workstation_id: "ws-1".to_owned(),
            })
            .unwrap();
        assert_eq!(
            response.status,
            crate::proto::WorkstationStatus::Suspending as i32
        );
        assert_eq!(response.message, "draining");
        let response = client
            .resume_workstation(&ResumeWorkstationRequest {
                workstation_id: "ws-1".to_owned(),
            })
            .unwrap();
        assert_eq!(
            response.status,
            crate::proto::WorkstationStatus::Error as i32
        );
        let response = client
            .delete_workstation(&DeleteWorkstationRequest {
                workstation_id: "ws-1".to_owned(),
            })
            .unwrap();
        assert!(!response.success);
        assert_eq!(response.message, "deletion denied");
        worker.join().unwrap();
    }

    #[test]
    fn lifecycle_transport_loss_never_repeats_the_mutation() {
        use std::io::BufRead;
        use std::net::{Shutdown, TcpListener};
        for method in [
            "SuspendWorkstation",
            "ResumeWorkstation",
            "DeleteWorkstation",
        ] {
            let server = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = Client::new(&format!("http://{}", server.local_addr().unwrap())).unwrap();
            let worker = thread::spawn(move || {
                let (stream, _) = server.accept().unwrap();
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                reader.read_exact(&mut vec![0; length]).unwrap();
                stream.shutdown(Shutdown::Both).unwrap();
                server.set_nonblocking(true).unwrap();
                thread::sleep(Duration::from_millis(100));
                assert!(
                    matches!(server.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
                );
            });
            let result = match method {
                "SuspendWorkstation" => client
                    .suspend_workstation(&SuspendWorkstationRequest {
                        workstation_id: "ws-1".to_owned(),
                    })
                    .map(|_| ()),
                "ResumeWorkstation" => client
                    .resume_workstation(&ResumeWorkstationRequest {
                        workstation_id: "ws-1".to_owned(),
                    })
                    .map(|_| ()),
                _ => client
                    .delete_workstation(&DeleteWorkstationRequest {
                        workstation_id: "ws-1".to_owned(),
                    })
                    .map(|_| ()),
            };
            assert!(result.is_err());
            worker.join().unwrap();
        }
    }

    #[test]
    fn execute_and_follow_use_exact_arguments_and_connect_framing() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let client = Client::new(&format!("http://{}", server.server_addr()))
            .unwrap()
            .with_session_credential("session")
            .unwrap();
        let worker = thread::spawn(move || {
            let mut request = server.recv().unwrap();
            assert_eq!(request.url(), format!("/{SERVICE}/ExecuteProcess"));
            let mut body = String::new();
            request.as_reader().read_to_string(&mut body).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({
                    "workstationId":"ws-1", "command":"printf", "args":["%s", "literal $value; quoted"], "workingDir":"/tmp"
                })
            );
            request
                .respond(Response::from_string(r#"{"commandId":"cmd-1"}"#))
                .unwrap();

            let mut request = server.recv().unwrap();
            assert_eq!(request.url(), format!("/{SERVICE}/StreamCommandOutput"));
            for (header, expected) in [
                ("Content-Type", "application/connect+json"),
                ("Accept-Encoding", "identity"),
                ("Connect-Accept-Encoding", "identity"),
                ("Authorization", "BBIdentity session"),
            ] {
                assert_eq!(
                    request
                        .headers()
                        .iter()
                        .find(|h| h.field.equiv(header))
                        .unwrap()
                        .value
                        .as_str(),
                    expected
                );
            }
            let mut body = Vec::new();
            request.as_reader().read_to_end(&mut body).unwrap();
            assert_eq!(body[0], 0);
            assert_eq!(
                u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize,
                body.len() - 5
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body[5..]).unwrap(),
                serde_json::json!({"workstationId":"ws-1", "commandId":"cmd-1", "follow":true})
            );
            let body = [
                frame(
                    0,
                    r#"{"stream":"STREAM_TYPE_STDOUT","data":"b3V0","resumeId":"1"}"#,
                ),
                frame(
                    0,
                    r#"{"stream":"STREAM_TYPE_STDERR","data":"ZXJy","resumeId":"2"}"#,
                ),
                frame(0, r#"{"exitCode":7,"eof":true}"#),
                frame(2, "{}"),
            ]
            .concat();
            request
                .respond(Response::from_data(body).with_header(
                    Header::from_bytes("Content-Type", "application/connect+json").unwrap(),
                ))
                .unwrap();
        });
        let execution = client
            .execute_process(&ExecuteProcessRequest {
                workstation_id: "ws-1".to_owned(),
                command: "printf".to_owned(),
                args: vec!["%s".to_owned(), "literal $value; quoted".to_owned()],
                working_dir: "/tmp".to_owned(),
                ..Default::default()
            })
            .unwrap();
        let mut chunks = Vec::new();
        client
            .stream_command_output(
                &StreamCommandOutputRequest {
                    workstation_id: "ws-1".to_owned(),
                    command_id: execution.command_id,
                    follow: true,
                    ..Default::default()
                },
                |chunk| {
                    chunks.push(chunk);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(chunks[0].data, b"out");
        assert_eq!(chunks[1].data, b"err");
        assert_eq!(chunks[2].exit_code, Some(7));
        worker.join().unwrap();
    }

    #[test]
    fn frames_handle_short_reads_and_silent_terminal_processes() {
        struct ShortReads(std::io::Cursor<Vec<u8>>);
        impl Read for ShortReads {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let length = buffer.len().min(1);
                self.0.read(&mut buffer[..length])
            }
        }
        let client = Client::new("https://example.com").unwrap();
        let bytes = [frame(0, r#"{"exitCode":0}"#), frame(2, "{}")].concat();
        let mut exit = None;
        client
            .read_output_stream(ShortReads(std::io::Cursor::new(bytes)), &mut |chunk| {
                assert!(chunk.data.is_empty());
                exit = chunk.exit_code;
                Ok(())
            })
            .unwrap();
        assert_eq!(exit, Some(0));
    }

    #[test]
    fn malformed_or_incomplete_streams_are_never_successful() {
        let client = Client::new("https://example.com").unwrap();
        for bytes in [
            vec![],
            vec![0, 0],
            frame(0, r#"{"exitCode":0,"eof":true}"#),
            vec![0, 0, 0, 0, 4, b'{'],
            frame(1, "{}"),
            frame(3, "{}"),
            vec![0, 0, 32, 0, 1],
            frame(2, "invalid"),
        ] {
            assert!(client
                .read_output_stream(bytes.as_slice(), &mut |_| Ok(()))
                .is_err());
        }
        let bytes = [frame(0, "{}"), frame(2, "{}")].concat();
        let error = client
            .read_output_stream(bytes.as_slice(), &mut |_| anyhow::bail!("output closed"))
            .unwrap_err();
        assert_eq!(error.to_string(), "output closed");
    }

    #[test]
    fn stream_trailer_errors_and_reflected_secrets_are_safe() {
        let client = Client::new("https://example.com")
            .unwrap()
            .with_session_credential("secret-session")
            .unwrap();
        let bytes = frame(
            2,
            r#"{"error":{"code":"permission_denied","message":"denied"},"metadata":{"x-test":["value"]}}"#,
        );
        let error = client
            .read_output_stream(bytes.as_slice(), &mut |_| Ok(()))
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<RpcError>().unwrap().code,
            "permission_denied"
        );
        let bytes = frame(
            2,
            r#"{"error":{"code":"unauthenticated","message":"secret-session"}}"#,
        );
        let error = client
            .read_output_stream(bytes.as_slice(), &mut |_| Ok(()))
            .unwrap_err();
        assert!(!format!("{error:?}").contains("secret-session"));
        let bytes = frame(0, r#"{"data":"c2VjcmV0LXNlc3Npb24="}"#);
        let error = client
            .read_output_stream(bytes.as_slice(), &mut |_| {
                panic!("secret must not reach callback")
            })
            .unwrap_err();
        assert!(!format!("{error:?}").contains("secret-session"));
    }

    #[test]
    fn streaming_http_errors_validate_auth_encoding_and_content_type() {
        for (status, content_type, compression, body) in [
            (
                401,
                "application/json",
                None,
                r#"{"code":"unauthenticated","message":"secret-session"}"#,
            ),
            (200, "application/json", None, "{}"),
            (200, "application/connect+json", Some("gzip"), "{}"),
        ] {
            let server = Server::http("127.0.0.1:0").unwrap();
            let client = Client::new(&format!("http://{}", server.server_addr()))
                .unwrap()
                .with_session_credential("secret-session")
                .unwrap();
            let worker = thread::spawn(move || {
                let mut response = Response::from_string(body)
                    .with_status_code(status)
                    .with_header(Header::from_bytes("Content-Type", content_type).unwrap());
                if status == 401 {
                    response = response
                        .with_header(Header::from_bytes("X-Request-Id", "stream-req-401").unwrap());
                }
                if let Some(compression) = compression {
                    response = response.with_header(
                        Header::from_bytes("Connect-Content-Encoding", compression).unwrap(),
                    );
                }
                server.recv().unwrap().respond(response).unwrap();
            });
            let error = client
                .stream_command_output(&StreamCommandOutputRequest::default(), |_| {
                    panic!("invalid response must not reach callback")
                })
                .unwrap_err();
            if status == 401 {
                assert_eq!(
                    error.downcast_ref::<RpcError>().unwrap().code,
                    "unauthenticated"
                );
                assert!(error.to_string().contains("x-request-id=stream-req-401"));
                assert!(error.to_string().contains("Blox StreamCommandOutput"));
            }
            assert!(!format!("{error:?}").contains("secret-session"));
            worker.join().unwrap();
        }
    }

    #[test]
    fn connect_request_uses_typed_json_and_credentials() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}/prefix", server.server_addr());
        let worker = thread::spawn(move || {
            let mut request = server.recv().unwrap();
            assert_eq!(request.method().as_str(), "POST");
            assert_eq!(request.url(), format!("/prefix/{SERVICE}/ListWorkstations"));
            for (name, expected) in [
                ("Content-Type", "application/json"),
                ("Connect-Protocol-Version", "1"),
                ("Authorization", "BBIdentity session"),
            ] {
                let value = request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv(name))
                    .unwrap();
                assert_eq!(value.value.as_str(), expected);
            }
            let mut body = String::new();
            request.as_reader().read_to_string(&mut body).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"includeDeleted": false})
            );
            request.respond(Response::from_string(r#"{"totalCount":"9007199254740993","workstations":[{"name":"test","status":"WORKSTATION_STATUS_RUNNING"}]}"#)
                .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())).unwrap();
        });
        let client = Client::new(&url)
            .unwrap()
            .with_session_credential("session")
            .unwrap();
        let response = client
            .list_workstations(&ListWorkstationsRequest {
                include_deleted: Some(false),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(response.total_count, 9_007_199_254_740_993);
        worker.join().unwrap();
    }

    #[test]
    fn session_auth_uses_the_existing_builderlab_scheme() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let client = Client::new(&format!("http://{}", server.server_addr()))
            .unwrap()
            .with_session_credential("session")
            .unwrap();
        let worker = thread::spawn(move || {
            let request = server.recv().unwrap();
            assert_eq!(
                request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Authorization"))
                    .unwrap()
                    .value
                    .as_str(),
                "BBIdentity session"
            );
            request.respond(Response::from_string("{}")).unwrap();
        });
        client.get_workstation("example").unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn connect_errors_keep_machine_readable_codes() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let client = Client::new(&format!("http://{}", server.server_addr())).unwrap();
        let worker = thread::spawn(move || {
            let request = server.recv().unwrap();
            assert!(!request
                .headers()
                .iter()
                .any(|h| h.field.equiv("X-Forwarded-Identity-Token")));
            request
                .respond(
                    Response::from_string(
                        r#"{"code":"not_found","message":"workstation missing"}"#,
                    )
                    .with_status_code(404),
                )
                .unwrap();
        });
        let error = client.get_workstation("missing").unwrap_err();
        assert_eq!(error.downcast_ref::<RpcError>().unwrap().code, "not_found");
        worker.join().unwrap();
    }

    #[test]
    fn rejects_urls_and_credentials_that_could_leak_headers() {
        for url in [
            "file:///tmp/blox",
            "https://user:password@example.com",
            "https://example.com?token=x",
            "https://example.com#fragment",
        ] {
            assert!(Client::new(url).is_err());
        }
        assert!(Client::new("https://example.com")
            .unwrap()
            .with_session_credential("bad\ntoken")
            .is_err());
    }

    fn response_error(status: u16, body: String) -> anyhow::Error {
        let server = Server::http("127.0.0.1:0").unwrap();
        let client = Client::new(&format!("http://{}", server.server_addr()))
            .unwrap()
            .with_session_credential("secret-session")
            .unwrap();
        let worker = thread::spawn(move || {
            server
                .recv()
                .unwrap()
                .respond(Response::from_string(body).with_status_code(status))
                .unwrap();
        });
        let error = client.get_workstation("example").unwrap_err();
        worker.join().unwrap();
        error
    }

    #[test]
    fn response_errors_redact_reflected_sessions_and_json_parse_details() {
        let error = response_error(401, r#"{"code":"unauthenticated","message":"BBIdentity secret-session is invalid: secret-session"}"#.to_owned());
        assert_eq!(
            error.downcast_ref::<RpcError>().unwrap().code,
            "unauthenticated"
        );
        assert!(!format!("{error:?}").contains("secret-session"));
        let error = response_error(
            200,
            r#"{"workstation":{"status":"secret-session"}}"#.to_owned(),
        );
        assert!(!format!("{error:?}").contains("secret-session"));
    }

    #[test]
    fn non_connect_503_includes_operation_status_request_id_and_safe_json_detail() {
        let client = Client::new("https://blox.example").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("req-123.ab"));
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        let error = client.response_error(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            br#"{"message":"upstream unavailable"}"#,
            "GetWorkstation",
            &headers,
        );
        let message = error.to_string();
        assert!(message.contains("Blox GetWorkstation failed with HTTP 503"));
        assert!(message.contains("x-request-id=req-123.ab"));
        assert!(message.contains("content-type=application/json; charset=utf-8"));
        assert!(message.contains("detail=upstream unavailable"));
        assert_eq!(
            error.downcast_ref::<RpcError>().unwrap().code,
            "unavailable"
        );
    }

    #[test]
    fn response_error_details_omit_sensitive_or_unsafe_values() {
        let client = Client::new("https://blox.example")
            .unwrap()
            .with_session_credential("secret-session")
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("secret-session"));
        headers.insert(
            "x-correlation-id",
            HeaderValue::from_static("req/with?query"),
        );
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        let error = client.response_error(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            br#"{"message":"upstream token=do-not-print"}"#,
            "GetWorkstation",
            &headers,
        );
        let message = error.to_string();
        assert!(message.contains("HTTP 503"));
        assert!(!message.contains("secret-session"));
        assert!(!message.contains("req/with?query"));
        assert!(message.contains("content-type=text/html"));
        assert!(!message.contains("do-not-print"));
        assert!(!message.contains("detail="));

        let body = serde_json::json!({
            "message": "reflected secret-\u{001b}[31msession"
        })
        .to_string();
        let detail_headers = HeaderMap::from_iter([(
            "content-type".parse().unwrap(),
            HeaderValue::from_static("application/json"),
        )]);
        let error = client.response_error(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            body.as_bytes(),
            "GetWorkstation",
            &detail_headers,
        );
        assert!(error.to_string().contains("[REDACTED]"));
        assert!(!error.to_string().contains("secret-session"));
    }

    #[test]
    fn unary_503_diagnostics_include_http_response_headers() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let client = Client::new(&format!("http://{}", server.server_addr())).unwrap();
        let worker = thread::spawn(move || {
            server
                .recv()
                .unwrap()
                .respond(
                    Response::from_string(r#"{"message":"upstream unavailable"}"#)
                        .with_status_code(503)
                        .with_header(
                            Header::from_bytes("Content-Type", "application/json").unwrap(),
                        )
                        .with_header(Header::from_bytes("X-Request-Id", "unary-req-503").unwrap()),
                )
                .unwrap();
        });
        let error = client.get_workstation("ws-1").unwrap_err();
        assert!(error
            .to_string()
            .contains("Blox GetWorkstation failed with HTTP 503"));
        assert!(error.to_string().contains("x-request-id=unary-req-503"));
        assert!(error.to_string().contains("detail=upstream unavailable"));
        worker.join().unwrap();
    }

    #[test]
    fn response_error_details_omit_urls_and_strip_ansi_and_controls() {
        let client = Client::new("https://blox.example").unwrap();
        let headers = HeaderMap::from_iter([(
            "content-type".parse().unwrap(),
            HeaderValue::from_static("application/problem+json"),
        )]);
        let body = serde_json::json!({
            "detail": "reset\u{001b}[31m\nvia https://mesh.example/path?token=hidden"
        })
        .to_string();
        let error = client.response_error(
            reqwest::StatusCode::BAD_GATEWAY,
            body.as_bytes(),
            "GetWorkstation",
            &headers,
        );
        let message = error.to_string();
        assert!(message.contains("response detail omitted"));
        assert!(!message.contains("\u{001b}"));
        assert!(!message.contains("token=hidden"));

        let body = serde_json::json!({
            "detail": "reset\u{001b}[31m\nvia\u{202e} now"
        })
        .to_string();
        let error = client.response_error(
            reqwest::StatusCode::BAD_GATEWAY,
            body.as_bytes(),
            "GetWorkstation",
            &headers,
        );
        let message = error.to_string();
        assert!(message.contains("detail=resetvia now"));
        assert!(!message.contains("\u{001b}"));
        assert!(!message.contains("\u{202e}"));

        let long_detail = format!("{{\"message\":\"{}\"}}", "x".repeat(400));
        let error = client.response_error(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            long_detail.as_bytes(),
            "GetWorkstation",
            &headers,
        );
        assert!(error.to_string().len() < 400);
        assert!(error.to_string().contains('…'));
    }

    #[test]
    fn response_error_without_safe_headers_or_body_still_names_operation_and_status() {
        let client = Client::new("https://blox.example").unwrap();
        let error = client.response_error(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            b"<html>proxy error</html>",
            "GetWorkstation",
            &HeaderMap::new(),
        );
        assert_eq!(
            error.to_string(),
            "unavailable: Blox GetWorkstation failed with HTTP 503 Service Unavailable"
        );
    }

    #[test]
    fn non_json_auth_failures_keep_stable_codes() {
        for (status, code) in [(401, "unauthenticated"), (403, "permission_denied")] {
            let error = response_error(status, "secret-session".to_owned());
            assert_eq!(error.downcast_ref::<RpcError>().unwrap().code, code);
            assert!(!format!("{error:?}").contains("secret-session"));
        }
    }

    #[test]
    fn successful_fields_and_object_keys_cannot_reflect_credentials() {
        for body in [
            r#"{"workstation":{"name":"secret-session"}}"#,
            r#"{"secret-session":"ignored"}"#,
        ] {
            let error = response_error(200, body.to_owned());
            assert!(error
                .to_string()
                .contains("reflected authentication credentials"));
            assert!(!format!("{error:?}").contains("secret-session"));
        }
    }

    #[test]
    fn responses_are_bounded() {
        let error = response_error(200, "x".repeat(MAX_RESPONSE_BYTES as usize + 1));
        assert!(error.to_string().contains("exceeds 2 MiB"));
    }

    #[test]
    fn redirects_do_not_forward_session_credentials() {
        let target = Server::http("127.0.0.1:0").unwrap();
        let server = Server::http("127.0.0.1:0").unwrap();
        let client = Client::new(&format!("http://{}", server.server_addr()))
            .unwrap()
            .with_session_credential("secret-session")
            .unwrap();
        let location = format!("http://{}/capture", target.server_addr());
        let worker = thread::spawn(move || {
            server
                .recv()
                .unwrap()
                .respond(
                    Response::empty(307)
                        .with_header(Header::from_bytes("Location", location).unwrap()),
                )
                .unwrap();
        });
        assert!(client.get_workstation("example").is_err());
        worker.join().unwrap();
        assert!(target
            .recv_timeout(Duration::from_millis(100))
            .unwrap()
            .is_none());
    }

    #[test]
    fn create_uses_sku_multiples_without_repository_or_resource_overrides() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let client = Client::new(&format!("http://{}", server.server_addr()))
            .unwrap()
            .with_session_credential("session")
            .unwrap();
        let worker = thread::spawn(move || {
            let mut request = server.recv().unwrap();
            assert_eq!(request.url(), format!("/{SERVICE}/StartWorkstation"));
            assert_eq!(
                request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Authorization"))
                    .unwrap()
                    .value
                    .as_str(),
                "BBIdentity session"
            );
            let mut body = String::new();
            request.as_reader().read_to_string(&mut body).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({
                    "name": "new-workstation", "computeSku": {"code": "DEFAULT_AMD64", "multiple": 3}, "creationClient": "builderlab_cli"
                })
            );
            request
                .respond(Response::from_string(
                    r#"{"workstationId":"ws-created","status":"WORKSTATION_STATUS_CREATING"}"#,
                ))
                .unwrap();
        });
        let response = client
            .start_workstation(&StartWorkstationRequest {
                name: Some("new-workstation".to_owned()),
                compute_sku: Some(crate::proto::ComputeSkuSelection {
                    code: "DEFAULT_AMD64".to_owned(),
                    multiple: 3,
                }),
                creation_client: "builderlab_cli".to_owned(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(response.workstation_id, "ws-created");
        worker.join().unwrap();
    }

    #[test]
    fn catalog_discovery_uses_empty_typed_request() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let client = Client::new(&format!("http://{}", server.server_addr())).unwrap();
        let worker = thread::spawn(move || {
            let mut request = server.recv().unwrap();
            assert_eq!(request.url(), format!("/{SERVICE}/ListComputeProviders"));
            let mut body = String::new();
            request.as_reader().read_to_string(&mut body).unwrap();
            assert_eq!(body, "{}");
            request
                .respond(Response::from_string(
                    r#"{"computeSkus":[{"code":"DEFAULT_AMD64","maxMultiple":3}]}"#,
                ))
                .unwrap();
        });
        assert_eq!(
            client.list_compute_providers().unwrap().compute_skus[0].max_multiple,
            3
        );
        worker.join().unwrap();
    }

    #[test]
    fn ambiguous_create_response_is_not_retried() {
        use std::io::BufRead;
        use std::net::{Shutdown, TcpListener};
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Client::new(&format!("http://{}", server.local_addr().unwrap())).unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = server.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            reader.read_exact(&mut vec![0; length]).unwrap();
            stream.shutdown(Shutdown::Both).unwrap();
            server.set_nonblocking(true).unwrap();
            thread::sleep(Duration::from_millis(100));
            assert!(
                matches!(server.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
        });
        assert!(client
            .start_workstation(&StartWorkstationRequest::default())
            .is_err());
        worker.join().unwrap();

        let server = Server::http("127.0.0.1:0").unwrap();
        let client = Client::new(&format!("http://{}", server.server_addr())).unwrap();
        let worker = thread::spawn(move || {
            server
                .recv()
                .unwrap()
                .respond(Response::from_string("invalid-json"))
                .unwrap();
            assert!(server
                .recv_timeout(Duration::from_millis(100))
                .unwrap()
                .is_none());
        });
        assert!(client
            .start_workstation(&StartWorkstationRequest::default())
            .is_err());
        worker.join().unwrap();
    }
}
