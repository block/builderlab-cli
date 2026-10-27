use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{ACCEPT, COOKIE, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::StatusCode as HttpStatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::auth::SESSION_CREDENTIAL_HEADER;
use crate::auth_storage::StoredSessionCredential;

pub const CLI_USER_AGENT: &str = "sq-kgoose-bl-auth-login";

// Kept in memory for one browser login; never persist or log the verifier.
pub struct LoginAttempt {
    state: String,
    code_verifier: String,
}

impl LoginAttempt {
    pub fn new() -> Result<Self> {
        Ok(Self {
            state: random_token()?,
            code_verifier: random_token()?,
        })
    }

    pub fn state(&self) -> &str {
        &self.state
    }

    pub fn code_verifier(&self) -> &str {
        &self.code_verifier
    }

    fn code_challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.code_verifier.as_bytes()))
    }
}

fn random_token() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| anyhow!("generate secure login randomness"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Session type requested from `/v1/auth/login`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginType {
    /// CLI session sent to BuilderLab APIs in `X-BB-Session-Credential`.
    Cli,
    /// Tenant-wide hosted-app session, sent to hosted apps only as the
    /// hosted-site cookie.
    CliHosted,
}

impl LoginType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::CliHosted => "cli_hosted",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginExchangeResponse {
    pub session_credential: String,
    pub expires_at: String,
}

/// Exchange response for a `type=cli_hosted` login code.
#[derive(Deserialize)]
pub struct HostedLoginExchangeResponse {
    pub session_credential: String,
    pub cookie_name: String,
    pub cookie_domain: String,
    pub expires_at: String,
}

// Never print the credential through Debug.
impl std::fmt::Debug for HostedLoginExchangeResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostedLoginExchangeResponse")
            .field("cookie_name", &self.cookie_name)
            .field("cookie_domain", &self.cookie_domain)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthMeResponse {
    pub subject: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub expires_at: Option<String>,
    pub workspaces: AuthMeWorkspaces,
    pub account_status: Option<String>,
    pub enabled_products: Option<Vec<String>>,
}

impl AuthMeResponse {
    pub fn active_workspace_name(&self) -> Result<&str> {
        self.workspaces
            .active
            .first()
            .map(|workspace| workspace.name.as_str())
            .ok_or_else(|| anyhow!("/v1/auth/me returned no active workspaces"))
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthMeWorkspaces {
    pub active: Vec<AuthMeWorkspace>,
}

#[derive(Debug, Deserialize)]
pub struct AuthMeWorkspace {
    pub name: String,
}

#[derive(Debug)]
pub struct VerifiedLoginSession {
    pub credential: StoredSessionCredential,
    pub me: AuthMeResponse,
}

#[derive(Serialize)]
struct LoginExchangeRequest<'a> {
    code: &'a str,
    code_verifier: &'a str,
}

pub fn build_auth_http_client(timeout: Duration) -> Result<Client> {
    ClientBuilder::new()
        .redirect(Policy::none())
        .timeout(timeout)
        .build()
        .context("build auth login HTTP client")
}

pub fn exchange_login_code(
    client: &Client,
    playpen: Option<&str>,
    server_url: &str,
    code: &str,
    code_verifier: &str,
) -> Result<LoginExchangeResponse> {
    exchange_login_code_as(client, playpen, server_url, code, code_verifier)
}

pub fn exchange_hosted_login_code(
    client: &Client,
    playpen: Option<&str>,
    server_url: &str,
    code: &str,
    code_verifier: &str,
) -> Result<HostedLoginExchangeResponse> {
    exchange_login_code_as(client, playpen, server_url, code, code_verifier)
}

fn exchange_login_code_as<T: serde::de::DeserializeOwned>(
    client: &Client,
    playpen: Option<&str>,
    server_url: &str,
    code: &str,
    code_verifier: &str,
) -> Result<T> {
    let url = auth_url(server_url, "/v1/auth/login/exchange")?;
    let mut request = client
        .post(url)
        .header(USER_AGENT, CLI_USER_AGENT)
        .header(ACCEPT, "application/json")
        .json(&LoginExchangeRequest {
            code,
            code_verifier,
        });
    if let Some(baggage) = playpen_baggage(playpen) {
        request = request.header("Baggage", baggage);
    }
    let response = request.send().context("exchange login code")?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!("/v1/auth/login/exchange failed with {status}"));
    }
    let body = response.text().context("read login exchange response")?;
    serde_json::from_str(&body).context("parse login exchange response")
}

pub fn exchange_login_code_and_verify(
    client: &Client,
    playpen: Option<&str>,
    server_url: &str,
    code: &str,
    code_verifier: &str,
) -> Result<VerifiedLoginSession> {
    let exchange = exchange_login_code(client, playpen, server_url, code, code_verifier)?;
    let credential = StoredSessionCredential {
        session_credential: exchange.session_credential,
        expires_at: Some(exchange.expires_at),
        ..Default::default()
    };
    let me =
        verify_session_credential(client, playpen, server_url, &credential)?.ok_or_else(|| {
            anyhow!("exchanged BuilderLab CLI auth session was rejected by /v1/auth/me")
        })?;
    Ok(VerifiedLoginSession { credential, me })
}

pub fn verify_session_credential(
    client: &Client,
    playpen: Option<&str>,
    server_url: &str,
    credential: &StoredSessionCredential,
) -> Result<Option<AuthMeResponse>> {
    let Some(session_credential) = credential.session_credential_header_value() else {
        return Ok(None);
    };
    let url = auth_url(server_url, "/v1/auth/me")?;
    let mut request = client
        .get(url)
        .header(USER_AGENT, CLI_USER_AGENT)
        .header(ACCEPT, "application/json")
        .header(SESSION_CREDENTIAL_HEADER, session_credential);
    if let Some(baggage) = playpen_baggage(playpen) {
        request = request.header("Baggage", baggage);
    }
    let response = request
        .send()
        .context("verify stored BuilderLab CLI auth session")?;
    let status = response.status();
    if status == HttpStatusCode::UNAUTHORIZED || status == HttpStatusCode::FORBIDDEN {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(anyhow!("/v1/auth/me failed with {status}"));
    }
    let body = response.text().context("read /v1/auth/me response")?;
    let me: AuthMeResponse = serde_json::from_str(&body).context("parse /v1/auth/me response")?;
    Ok(Some(me))
}

pub fn logout_session_credential(
    client: &Client,
    playpen: Option<&str>,
    server_url: &str,
    credential: &StoredSessionCredential,
) -> Result<bool> {
    let Some(session_credential) = credential.session_credential_header_value() else {
        return Ok(false);
    };
    post_logout(
        client,
        playpen,
        server_url,
        SESSION_CREDENTIAL_HEADER,
        &session_credential,
        "destroy stored BuilderLab CLI auth session",
    )
}

/// Revoke a `cli_hosted` session. The backend accepts it only the way hosted
/// apps do: as the hosted-site cookie.
pub fn logout_hosted_session_credential(
    client: &Client,
    playpen: Option<&str>,
    server_url: &str,
    credential: &StoredSessionCredential,
) -> Result<bool> {
    let (Some(cookie_name), Some(session_credential)) = (
        credential.cookie_name.as_deref(),
        credential.session_credential_header_value(),
    ) else {
        return Ok(false);
    };
    post_logout(
        client,
        playpen,
        server_url,
        COOKIE.as_str(),
        &format!("{cookie_name}={session_credential}"),
        "destroy stored BuilderLab hosted-app session",
    )
}

fn post_logout(
    client: &Client,
    playpen: Option<&str>,
    server_url: &str,
    credential_header: &str,
    credential_value: &str,
    context: &'static str,
) -> Result<bool> {
    let url = auth_url(server_url, "/v1/auth/logout")?;
    let mut request = client
        .post(url)
        .header(USER_AGENT, CLI_USER_AGENT)
        .header(ACCEPT, "application/json")
        .header(credential_header, credential_value);
    if let Some(baggage) = playpen_baggage(playpen) {
        request = request.header("Baggage", baggage);
    }
    let response = request.send().context(context)?;
    let status = response.status();
    if status == HttpStatusCode::UNAUTHORIZED || status == HttpStatusCode::FORBIDDEN {
        return Ok(false);
    }
    if !status.is_success() {
        return Err(anyhow!("/v1/auth/logout failed with {status}"));
    }
    Ok(true)
}

pub fn login_url(server_url: &str, callback_url: &str, attempt: &LoginAttempt) -> Result<Url> {
    login_url_for_type(server_url, callback_url, attempt, LoginType::Cli)
}

pub fn login_url_for_type(
    server_url: &str,
    callback_url: &str,
    attempt: &LoginAttempt,
    login_type: LoginType,
) -> Result<Url> {
    let mut url = auth_url(server_url, "/v1/auth/login")?;
    url.query_pairs_mut()
        .append_pair("type", login_type.as_str())
        .append_pair("returnTo", callback_url)
        .append_pair("state", attempt.state())
        .append_pair("code_challenge", &attempt.code_challenge())
        .append_pair("code_challenge_method", "S256");
    Ok(url)
}

pub fn auth_url(server_url: &str, path: &str) -> Result<Url> {
    let base = Url::parse(server_url).context("server URL must be absolute")?;
    let path = format!(
        "{}/{}",
        base.path().trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let mut url = base;
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

// Backend routing contract; preserve this key across CLI product renames.
pub fn playpen_baggage(playpen: Option<&str>) -> Option<String> {
    playpen.map(|playpen| format!("kgoose-builderbot-playpen={playpen}"))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use super::*;

    #[test]
    fn verify_session_credential_treats_unauthorized_as_invalid() {
        let server = TestServer::single(401, r#"{}"#);
        let client = build_auth_http_client(Duration::from_secs(5)).expect("client");
        let credential = StoredSessionCredential {
            session_credential: "expired-session".to_string(),
            expires_at: None,
            ..Default::default()
        };

        let verified = verify_session_credential(&client, None, &server.base_url, &credential)
            .expect("verify session");
        let request = server.finish_one();

        assert!(verified.is_none());
        assert_eq!(request.path, "/v1/auth/me");
        assert_eq!(
            request.bl_session_credential.as_deref(),
            Some("expired-session")
        );
    }

    #[test]
    fn verify_session_credential_does_not_echo_failure_body() {
        let secret = "reflected_session_credential_123456";
        let server = TestServer::single(500, secret);
        let client = build_auth_http_client(Duration::from_secs(5)).expect("client");
        let credential = StoredSessionCredential {
            session_credential: secret.to_string(),
            expires_at: None,
            ..Default::default()
        };

        let error = verify_session_credential(&client, None, &server.base_url, &credential)
            .expect_err("reject failed session check");
        let request = server.finish_one();
        let message = format!("{error:#}");

        assert!(message.contains("/v1/auth/me failed with 500"));
        assert!(!message.contains(secret));
        assert_eq!(request.path, "/v1/auth/me");
    }

    #[test]
    fn verify_session_credential_skips_empty_stored_credential() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused server");
        let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
        let client = build_auth_http_client(Duration::from_secs(1)).expect("client");
        let credential = StoredSessionCredential {
            session_credential: String::new(),
            expires_at: None,
            ..Default::default()
        };

        let verified = verify_session_credential(&client, None, &base_url, &credential)
            .expect("verify session");

        assert!(verified.is_none());
    }

    #[test]
    fn logout_session_credential_posts_logout_and_accepts_success() {
        let server = TestServer::single(200, r#"{}"#);
        let client = build_auth_http_client(Duration::from_secs(5)).expect("client");
        let credential = StoredSessionCredential {
            session_credential: "valid-session".to_string(),
            expires_at: None,
            ..Default::default()
        };

        let logged_out = logout_session_credential(&client, None, &server.base_url, &credential)
            .expect("logout session");
        let request = server.finish_one();

        assert!(logged_out);
        assert_eq!(request.path, "/v1/auth/logout");
        assert_eq!(
            request.bl_session_credential.as_deref(),
            Some("valid-session")
        );
    }

    #[test]
    fn logout_session_credential_treats_unauthorized_as_already_invalid() {
        let server = TestServer::single(401, r#"{}"#);
        let client = build_auth_http_client(Duration::from_secs(5)).expect("client");
        let credential = StoredSessionCredential {
            session_credential: "expired-session".to_string(),
            expires_at: None,
            ..Default::default()
        };

        let logged_out = logout_session_credential(&client, None, &server.base_url, &credential)
            .expect("logout session");
        let request = server.finish_one();

        assert!(!logged_out);
        assert_eq!(request.path, "/v1/auth/logout");
        assert_eq!(
            request.bl_session_credential.as_deref(),
            Some("expired-session")
        );
    }

    #[test]
    fn logout_hosted_session_credential_sends_only_the_hosted_cookie() {
        let server = TestServer::single(200, r#"{}"#);
        let client = build_auth_http_client(Duration::from_secs(5)).expect("client");
        let credential = StoredSessionCredential {
            session_credential: "hosted-session".to_string(),
            cookie_name: Some("bb_hosted_session".to_string()),
            cookie_domain: Some("apps.example.test".to_string()),
            ..Default::default()
        };

        let revoked =
            logout_hosted_session_credential(&client, None, &server.base_url, &credential)
                .expect("logout hosted session");
        let request = server.finish_one();

        assert!(revoked);
        assert_eq!(request.path, "/v1/auth/logout");
        assert_eq!(
            request.cookie.as_deref(),
            Some("bb_hosted_session=hosted-session")
        );
        assert_eq!(request.bl_session_credential, None);
    }

    #[test]
    fn logout_hosted_session_credential_skips_sessions_without_a_cookie_name() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused server");
        let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
        let client = build_auth_http_client(Duration::from_secs(1)).expect("client");
        let credential = StoredSessionCredential {
            session_credential: "hosted-session".to_string(),
            ..Default::default()
        };

        assert!(
            !logout_hosted_session_credential(&client, None, &base_url, &credential)
                .expect("skip logout")
        );
    }

    #[test]
    fn verify_session_credential_accepts_successful_me_response() {
        let server = TestServer::single(
            200,
            r#"{"subject":"auth0|user_123","email":"test@example.com","name":"Test User","expires_at":"2026-06-15T00:00:00Z","roles":["ROLE_USER"],"workspaces":{"active":[{"name":"Test Workspace"},{"name":"Other Workspace"}]}}"#,
        );
        let client = build_auth_http_client(Duration::from_secs(5)).expect("client");
        let credential = StoredSessionCredential {
            session_credential: "valid-session".to_string(),
            expires_at: None,
            ..Default::default()
        };

        let verified = verify_session_credential(&client, None, &server.base_url, &credential)
            .expect("verify session")
            .expect("authenticated");
        let request = server.finish_one();

        assert_eq!(verified.subject.as_deref(), Some("auth0|user_123"));
        assert_eq!(verified.expires_at.as_deref(), Some("2026-06-15T00:00:00Z"));
        assert_eq!(
            verified.active_workspace_name().expect("active workspace"),
            "Test Workspace"
        );
        assert_eq!(
            request.bl_session_credential.as_deref(),
            Some("valid-session")
        );
        assert_eq!(request.path, "/v1/auth/me");
    }

    #[test]
    fn login_attempts_have_independent_random_state_and_verifiers() {
        let first = LoginAttempt::new().expect("first attempt");
        let second = LoginAttempt::new().expect("second attempt");
        for token in [
            first.state(),
            first.code_verifier(),
            second.state(),
            second.code_verifier(),
        ] {
            assert_eq!(token.len(), 43);
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(token)
                    .expect("base64url token")
                    .len(),
                32
            );
        }
        assert_ne!(first.state(), first.code_verifier());
        assert_ne!(first.state(), second.state());
        assert_ne!(first.code_verifier(), second.code_verifier());
    }

    #[test]
    fn exchange_failure_does_not_echo_secrets() {
        let secret = "reflected-code-and-verifier";
        let server = TestServer::single(400, secret);
        let client = build_auth_http_client(Duration::from_secs(5)).expect("client");
        let error = exchange_login_code(&client, None, &server.base_url, secret, secret)
            .expect_err("reject failed exchange");
        server.finish_one();
        assert!(error.to_string().contains("400"));
        assert!(!format!("{error:#}").contains(secret));
    }

    #[test]
    fn login_url_includes_state_and_s256_challenge_without_verifier() {
        let url = login_url(
            "https://example.com/cash-app/goose",
            "http://127.0.0.1:1234/callback",
            &LoginAttempt {
                state: "client-state".to_string(),
                code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
            },
        )
        .expect("login URL");

        assert_eq!(url.path(), "/cash-app/goose/v1/auth/login");
        let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(query["type"], "cli");
        assert_eq!(query["returnTo"], "http://127.0.0.1:1234/callback");
        assert_eq!(query["state"], "client-state");
        // RFC 7636 Appendix B S256 test vector.
        assert_eq!(
            query["code_challenge"],
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(query["code_challenge_method"], "S256");
        assert!(!query.contains_key("code_verifier"));
    }

    #[test]
    fn cli_hosted_login_url_uses_the_same_pkce_parameters() {
        let url = login_url_for_type(
            "https://example.com/cash-app/goose",
            "http://127.0.0.1:1234/callback",
            &LoginAttempt {
                state: "client-state".to_string(),
                code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
            },
            LoginType::CliHosted,
        )
        .expect("login URL");

        assert_eq!(url.path(), "/cash-app/goose/v1/auth/login");
        let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(query["type"], "cli_hosted");
        assert_eq!(query["returnTo"], "http://127.0.0.1:1234/callback");
        assert_eq!(query["state"], "client-state");
        assert_eq!(
            query["code_challenge"],
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(query["code_challenge_method"], "S256");
        assert!(!query.contains_key("code_verifier"));
    }

    #[test]
    fn hosted_exchange_returns_cookie_metadata_without_debug_leaks() {
        let server = TestServer::single(
            200,
            r#"{"session_credential":"hosted-secret","cookie_name":"bb_hosted_session","cookie_domain":"apps.block.builderlab.xyz","expires_at":"2026-06-15T00:00:00Z"}"#,
        );
        let client = build_auth_http_client(Duration::from_secs(5)).expect("client");

        let exchange = exchange_hosted_login_code(
            &client,
            None,
            &server.base_url,
            "one-time-code",
            "test-verifier",
        )
        .expect("hosted exchange");
        let request = server.finish_one();

        assert_eq!(request.path, "/v1/auth/login/exchange");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&request.body).expect("exchange JSON"),
            serde_json::json!({"code": "one-time-code", "code_verifier": "test-verifier"})
        );
        assert_eq!(exchange.session_credential, "hosted-secret");
        assert_eq!(exchange.cookie_name, "bb_hosted_session");
        assert_eq!(exchange.cookie_domain, "apps.block.builderlab.xyz");
        assert_eq!(exchange.expires_at, "2026-06-15T00:00:00Z");
        assert!(!format!("{exchange:?}").contains("hosted-secret"));
    }

    #[test]
    fn login_exchange_sends_verifier_and_returns_verified_session() {
        let server = TestServer::start(vec![
            (
                200,
                r#"{"session_credential":"session","expires_at":"2026-06-15T00:00:00Z"}"#,
            ),
            (
                200,
                r#"{"subject":"auth0|user_123","email":"test@example.com","name":"Test User","expires_at":"2026-06-16T00:00:00Z","roles":["ROLE_USER"],"workspaces":{"active":[{"name":"Test Workspace"},{"name":"Other Workspace"}]}}"#,
            ),
        ]);
        let client = build_auth_http_client(Duration::from_secs(5)).expect("client");

        let verified = exchange_login_code_and_verify(
            &client,
            None,
            &server.base_url,
            "one-time-code",
            "test-verifier",
        )
        .expect("verified login");
        let requests = server.finish();

        assert_eq!(verified.credential.session_credential, "session");
        assert_eq!(
            verified.credential.expires_at.as_deref(),
            Some("2026-06-15T00:00:00Z")
        );
        assert_eq!(verified.me.subject.as_deref(), Some("auth0|user_123"));
        assert_eq!(
            verified
                .me
                .active_workspace_name()
                .expect("active workspace"),
            "Test Workspace"
        );
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].path, "/v1/auth/login/exchange");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&requests[0].body).expect("exchange JSON"),
            serde_json::json!({"code": "one-time-code", "code_verifier": "test-verifier"})
        );
        assert_eq!(requests[1].path, "/v1/auth/me");
        assert_eq!(
            requests[1].bl_session_credential.as_deref(),
            Some("session")
        );
    }

    #[test]
    fn exchange_login_code_and_verify_requires_auth_me_success() {
        let server = TestServer::start(vec![
            (
                200,
                r#"{"session_credential":"session","expires_at":"2026-06-15T00:00:00Z"}"#,
            ),
            (401, r#"{}"#),
        ]);
        let client = build_auth_http_client(Duration::from_secs(5)).expect("client");

        let error = exchange_login_code_and_verify(
            &client,
            None,
            &server.base_url,
            "one-time-code",
            "test-verifier",
        )
        .expect_err("auth/me rejection fails login");
        let requests = server.finish();

        assert!(
            format!("{error:#}").contains("rejected by /v1/auth/me"),
            "unexpected error: {error:#}"
        );
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].path, "/v1/auth/login/exchange");
        assert_eq!(requests[1].path, "/v1/auth/me");
    }

    struct RecordedRequest {
        path: String,
        bl_session_credential: Option<String>,
        cookie: Option<String>,
        body: String,
    }

    struct TestServer {
        base_url: String,
        handle: thread::JoinHandle<Vec<RecordedRequest>>,
    }

    impl TestServer {
        fn single(status: u16, body: &'static str) -> Self {
            Self::start(vec![(status, body)])
        }

        fn finish_one(self) -> RecordedRequest {
            let mut requests = self.finish();
            assert_eq!(requests.len(), 1, "expected a single request");
            requests.pop().expect("recorded request")
        }

        fn start(responses: Vec<(u16, &'static str)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
            let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
            let handle = thread::spawn(move || {
                let mut requests = Vec::new();
                for (status, body) in responses {
                    let (stream, _) = listener.accept().expect("accept request");
                    requests.push(handle_connection(stream, status, body));
                }
                requests
            });
            Self { base_url, handle }
        }

        fn finish(self) -> Vec<RecordedRequest> {
            self.handle.join().expect("join test server")
        }
    }

    fn handle_connection(mut stream: TcpStream, status: u16, body: &str) -> RecordedRequest {
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
        let mut request_line = String::new();
        reader.read_line(&mut request_line).expect("request line");
        let path = request_line
            .split_whitespace()
            .nth(1)
            .expect("request path")
            .to_string();

        let mut bl_session_credential = None;
        let mut cookie = None;
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("request header");
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().expect("content length");
                }
                if name.eq_ignore_ascii_case(SESSION_CREDENTIAL_HEADER) {
                    bl_session_credential = Some(value.trim().to_string());
                }
                if name.eq_ignore_ascii_case("cookie") {
                    cookie = Some(value.trim().to_string());
                }
            }
        }
        let mut body_bytes = vec![0; content_length];
        reader.read_exact(&mut body_bytes).expect("request body");
        let response = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
        RecordedRequest {
            path,
            bl_session_credential,
            cookie,
            body: String::from_utf8(body_bytes).expect("UTF-8 body"),
        }
    }
}
