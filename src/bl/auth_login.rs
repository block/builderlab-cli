//! Browser login for BuilderLab auth.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use builderlab_auth::auth_login::{
    build_auth_http_client, exchange_hosted_login_code, exchange_login_code_and_verify,
    login_url_for_type, logout_session_credential, verify_session_credential, AuthMeResponse,
    HostedLoginExchangeResponse, LoginAttempt, LoginType, VerifiedLoginSession,
};
use builderlab_auth::auth_storage::StoredSessionCredential;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tiny_http::{Header, Response, Server, StatusCode};
use url::Url;

use super::auth_storage::{
    hosted_session_storage_key, session_storage_key_from_config, SessionCredentialStorage,
};
use super::display::terminal_safe_text;
use super::skills_config::{kgoose_service_url, SkillsConfig};

const CALLBACK_PATH: &str = "/callback";
const LOGIN_CALLBACK_TIMEOUT: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, Copy)]
enum AuthCallbackPage {
    Success,
    Failure,
}

const AUTH_CALLBACK_PAGE_TEMPLATE: &str = include_str!("auth_callback.html");

#[derive(Debug, Serialize)]
pub struct BrowserLoginSummary {
    pub kgoose_base_url: String,
    pub kgoose_service_path: String,
    pub storage: String,
    pub source: BrowserLoginCredentialSource,
    pub workspace_name: String,
    pub expires_at: Option<String>,
    pub credential_prefix: Option<String>,
    pub credential_sha256_prefix: Option<String>,
}

struct BrowserLoginOutcome {
    summary: BrowserLoginSummary,
}

pub struct VerifiedStoredSession {
    pub credential: StoredSessionCredential,
    pub me: AuthMeResponse,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserLoginCredentialSource {
    Stored,
    BrowserLogin,
}

pub fn run_browser_login(
    config: &SkillsConfig,
    storage: &dyn SessionCredentialStorage,
) -> Result<BrowserLoginSummary> {
    run_browser_login_inner(config, storage).map(|outcome| outcome.summary)
}

fn run_browser_login_inner(
    config: &SkillsConfig,
    storage: &dyn SessionCredentialStorage,
) -> Result<BrowserLoginOutcome> {
    let service_url = kgoose_service_url(&config.kgoose_base_url, &config.kgoose_service_path);
    let client = build_auth_http_client(Duration::from_secs(30))?;
    let storage_key = session_storage_key_from_config(config);

    match storage.get(&storage_key)? {
        Some(stored) => {
            if let Some(me) = verify_session_credential(
                &client,
                config.playpen.as_deref(),
                &service_url,
                &stored,
            )? {
                auth_info(
                    config,
                    &format!(
                        "Found valid BuilderLab CLI auth session in {} storage",
                        storage.kind()
                    ),
                );
                let workspace_name = me.active_workspace_name()?.to_string();
                return Ok(BrowserLoginOutcome {
                    summary: BrowserLoginSummary {
                        kgoose_base_url: config.kgoose_base_url.clone(),
                        kgoose_service_path: config.kgoose_service_path.clone(),
                        storage: storage.kind().to_string(),
                        source: BrowserLoginCredentialSource::Stored,
                        workspace_name,
                        expires_at: me.expires_at.or_else(|| stored.expires_at.clone()),
                        credential_prefix: None,
                        credential_sha256_prefix: None,
                    },
                });
            }
            auth_info(
                config,
                &format!(
                    "Stored BuilderLab CLI auth session in {} storage is invalid",
                    storage.kind()
                ),
            );
        }
        None => {
            auth_info(
                config,
                &format!(
                    "No BuilderLab CLI auth session found in {} storage",
                    storage.kind()
                ),
            );
        }
    }

    let (code, attempt) = obtain_login_code(config, &service_url, LoginType::Cli)?;
    let verified = exchange_login_code_and_verify(
        &client,
        config.playpen.as_deref(),
        &service_url,
        &code,
        attempt.code_verifier(),
    )?;
    let (stored, me, workspace_name) =
        validate_and_store_login_credential(storage, &storage_key, verified)?;
    auth_info(
        config,
        &format!(
            "Stored BuilderLab CLI auth session in {} storage",
            storage.kind()
        ),
    );

    Ok(BrowserLoginOutcome {
        summary: BrowserLoginSummary {
            kgoose_base_url: config.kgoose_base_url.clone(),
            kgoose_service_path: config.kgoose_service_path.clone(),
            storage: storage.kind().to_string(),
            source: BrowserLoginCredentialSource::BrowserLogin,
            workspace_name,
            expires_at: me.expires_at.or_else(|| stored.expires_at.clone()),
            credential_prefix: Some(safe_prefix(&stored.session_credential)),
            credential_sha256_prefix: Some(sha256_prefix(&stored.session_credential)),
        },
    })
}

/// Run the `type=cli_hosted` browser login and store the hosted-app session.
///
/// All progress goes to stderr so stdout stays free for the response of the
/// command that needed the session. The exchanged credential is stored only
/// when the backend's cookie domain is exactly `hosted_domain`.
pub fn run_hosted_browser_login(
    config: &SkillsConfig,
    storage: &dyn SessionCredentialStorage,
    hosted_domain: &str,
) -> Result<StoredSessionCredential> {
    let service_url = kgoose_service_url(&config.kgoose_base_url, &config.kgoose_service_path);
    let client = build_auth_http_client(Duration::from_secs(30))?;
    let (code, attempt) = obtain_login_code(config, &service_url, LoginType::CliHosted)?;
    let exchange = exchange_hosted_login_code(
        &client,
        config.playpen.as_deref(),
        &service_url,
        &code,
        attempt.code_verifier(),
    )?;
    let credential = hosted_credential_from_exchange(exchange, hosted_domain)?;
    storage.set(
        &hosted_session_storage_key(config, hosted_domain),
        &credential,
    )?;
    eprintln!(
        "info: Stored BuilderLab hosted-app session for {hosted_domain} in {} storage",
        storage.kind()
    );
    Ok(credential)
}

fn hosted_credential_from_exchange(
    exchange: HostedLoginExchangeResponse,
    hosted_domain: &str,
) -> Result<StoredSessionCredential> {
    let cookie_domain = exchange
        .cookie_domain
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase();
    if cookie_domain != hosted_domain {
        return Err(anyhow!(
            "login returned a hosted-app session for `{}`, not `{hosted_domain}`; check that `bl` points at the backend for this tenant",
            terminal_safe_text(&cookie_domain)
        ));
    }
    if !is_cookie_name(&exchange.cookie_name) {
        return Err(anyhow!("login returned an invalid hosted-app cookie name"));
    }
    if !is_cookie_value(&exchange.session_credential) {
        return Err(anyhow!("login returned an invalid hosted-app session"));
    }
    Ok(StoredSessionCredential {
        session_credential: exchange.session_credential,
        expires_at: Some(exchange.expires_at),
        cookie_name: Some(exchange.cookie_name),
        cookie_domain: Some(cookie_domain),
    })
}

/// RFC 6265 cookie-name (an RFC 7230 token).
pub fn is_cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// RFC 6265 cookie-octets, without quotes.
pub fn is_cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(
            |byte| matches!(byte, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E),
        )
}

// Start the loopback callback server, open the browser, and wait for the
// one-time code. Interactive `bl auth login` prints to stdout; other callers
// keep stdout clean and print to stderr.
fn obtain_login_code(
    config: &SkillsConfig,
    service_url: &str,
    login_type: LoginType,
) -> Result<(String, LoginAttempt)> {
    let server = Server::http("127.0.0.1:0")
        .map_err(|error| anyhow!("listen on loopback callback port: {error}"))?;
    let callback_url = format!("http://{}{}", server.server_addr(), CALLBACK_PATH);
    let attempt = LoginAttempt::new()?;
    let login_url = login_url_for_type(service_url, &callback_url, &attempt, login_type)?;
    let expected_state = attempt.state().to_string();

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = receive_exchange_code(server, &expected_state);
        let _ = tx.send(result);
    });

    match login_type {
        LoginType::Cli => {
            if !config.json {
                println!("Opening BuilderLab auth login in your browser:");
                println!("{login_url}");
            }
            if let Err(error) = webbrowser::open(login_url.as_str()) {
                if config.json {
                    return Err(anyhow!(
                        "failed to open browser for BuilderLab auth login: {error}"
                    ));
                }
                println!("Could not open a browser automatically. Open the URL above manually.");
            }
        }
        LoginType::CliHosted => {
            eprintln!("Opening BuilderLab hosted-app login in your browser:");
            eprintln!("{login_url}");
            if webbrowser::open(login_url.as_str()).is_err() {
                eprintln!("Could not open a browser automatically. Open the URL above manually.");
            }
        }
    }

    let code = wait_for_exchange_code(&rx, LOGIN_CALLBACK_TIMEOUT)?;
    Ok((code, attempt))
}

pub fn verify_stored_session(
    config: &SkillsConfig,
    storage: &dyn SessionCredentialStorage,
) -> Result<Option<VerifiedStoredSession>> {
    let service_url = kgoose_service_url(&config.kgoose_base_url, &config.kgoose_service_path);
    let client = build_auth_http_client(Duration::from_secs(30))?;
    let storage_key = session_storage_key_from_config(config);
    verify_stored_session_with(storage, &storage_key, |stored| {
        verify_session_credential(&client, config.playpen.as_deref(), &service_url, stored)
    })
}

fn verify_stored_session_with<F>(
    storage: &dyn SessionCredentialStorage,
    storage_key: &super::auth_storage::SessionStorageKey,
    verify: F,
) -> Result<Option<VerifiedStoredSession>>
where
    F: FnOnce(&StoredSessionCredential) -> Result<Option<AuthMeResponse>>,
{
    let Some(stored) = storage.get(storage_key)? else {
        return Ok(None);
    };
    Ok(verify(&stored)?.map(|me| VerifiedStoredSession {
        credential: stored,
        me,
    }))
}

fn store_login_credential(
    storage: &dyn SessionCredentialStorage,
    storage_key: &super::auth_storage::SessionStorageKey,
    credential: StoredSessionCredential,
) -> Result<StoredSessionCredential> {
    storage.set(storage_key, &credential)?;
    Ok(credential)
}

fn validate_and_store_login_credential(
    storage: &dyn SessionCredentialStorage,
    storage_key: &super::auth_storage::SessionStorageKey,
    verified: VerifiedLoginSession,
) -> Result<(StoredSessionCredential, AuthMeResponse, String)> {
    let workspace_name = verified.me.active_workspace_name()?.to_string();
    let stored = store_login_credential(storage, storage_key, verified.credential)?;
    Ok((stored, verified.me, workspace_name))
}

pub fn logout_stored_session(
    config: &SkillsConfig,
    storage: &dyn SessionCredentialStorage,
) -> Result<bool> {
    let service_url = kgoose_service_url(&config.kgoose_base_url, &config.kgoose_service_path);
    let client = build_auth_http_client(Duration::from_secs(30))?;
    let storage_key = session_storage_key_from_config(config);
    let Some(stored) = storage.get(&storage_key)? else {
        return Ok(false);
    };

    logout_session_credential(&client, config.playpen.as_deref(), &service_url, &stored)
}

fn wait_for_exchange_code(
    receiver: &mpsc::Receiver<Result<String>>,
    timeout: Duration,
) -> Result<String> {
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(anyhow!(
            "BuilderLab CLI auth login timed out; rerun `bl auth login`"
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(anyhow!(
            "loopback auth server stopped before login completed"
        )),
    }
}

fn receive_exchange_code(server: Server, expected_state: &str) -> Result<String> {
    for request in server.incoming_requests() {
        let url = request.url().to_string();
        let parsed =
            Url::parse(&format!("http://127.0.0.1{url}")).context("parse loopback callback URL")?;
        if parsed.path() != CALLBACK_PATH {
            respond_text(
                request,
                StatusCode(404),
                "BuilderLab CLI auth is waiting for the callback.",
            )?;
            continue;
        }

        let mut states = parsed
            .query_pairs()
            .filter(|(key, _)| key == "state")
            .map(|(_, value)| value);
        if states.next().as_deref() != Some(expected_state) || states.next().is_some() {
            respond_auth_page(request, StatusCode(400), AuthCallbackPage::Failure)?;
            continue;
        }

        let result = callback_exchange_code(&parsed);
        let (status, page) = if result.is_ok() {
            (StatusCode(200), AuthCallbackPage::Success)
        } else {
            (StatusCode(400), AuthCallbackPage::Failure)
        };
        respond_auth_page(request, status, page)?;
        return result;
    }

    Err(anyhow!(
        "loopback auth server stopped without receiving a callback"
    ))
}

// Only parse the login result after the caller has validated the callback state.
fn callback_exchange_code(url: &Url) -> Result<String> {
    if url.query_pairs().any(|(key, _)| key == "error") {
        return Err(anyhow!("auth callback returned an authentication error"));
    }

    let mut codes = url
        .query_pairs()
        .filter(|(key, _)| key == "code")
        .map(|(_, value)| value);
    let code = codes
        .next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("auth callback did not include an exchange code"))?;
    if codes.next().is_some() {
        return Err(anyhow!("auth callback included duplicate exchange codes"));
    }
    Ok(code.into_owned())
}

fn respond_text(request: tiny_http::Request, status: StatusCode, body: &str) -> Result<()> {
    request
        .respond(
            Response::from_string(body)
                .with_status_code(status)
                .with_header(
                    Header::from_bytes("content-type", "text/plain; charset=utf-8").unwrap(),
                ),
        )
        .map_err(|error| anyhow!("write loopback callback response: {error}"))
}

fn respond_auth_page(
    request: tiny_http::Request,
    status: StatusCode,
    page: AuthCallbackPage,
) -> Result<()> {
    request
        .respond(
            Response::from_string(auth_callback_page(page))
                .with_status_code(status)
                .with_header(
                    Header::from_bytes("content-type", "text/html; charset=utf-8").unwrap(),
                )
                .with_header(Header::from_bytes("cache-control", "no-store").unwrap())
                .with_header(
                    Header::from_bytes(
                        "content-security-policy",
                        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'",
                    )
                    .unwrap(),
                )
                .with_header(Header::from_bytes("x-content-type-options", "nosniff").unwrap()),
        )
        .map_err(|error| anyhow!("write loopback callback response: {error}"))
}

fn auth_callback_page(page: AuthCallbackPage) -> String {
    let (title, class_name, icon, heading, message, terminal_message) = match page {
        AuthCallbackPage::Success => (
            "Signed in · BuilderLab CLI",
            "success",
            r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 4.25 4.25L19 6.5"/></svg>"#,
            "You’re signed in",
            "BuilderLab CLI authentication is complete. You can safely close this tab.",
            "Return to your terminal",
        ),
        AuthCallbackPage::Failure => (
            "Sign-in failed · BuilderLab CLI",
            "failure",
            r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.25" stroke-linecap="round"><path d="M7 7l10 10M17 7 7 17"/></svg>"#,
            "Sign-in didn’t finish",
            "BuilderLab CLI couldn’t complete authentication. Return to your terminal for details.",
            "Check your terminal",
        ),
    };

    AUTH_CALLBACK_PAGE_TEMPLATE
        .replace("__PAGE_TITLE__", title)
        .replace("__PAGE_CLASS__", class_name)
        .replace("__STATUS_ICON__", icon)
        .replace("__HEADING__", heading)
        .replace("__MESSAGE__", message)
        .replace("__TERMINAL_MESSAGE__", terminal_message)
}

fn safe_prefix(value: &str) -> String {
    value.chars().take(8).collect()
}

fn sha256_prefix(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn auth_info(config: &SkillsConfig, message: &str) {
    if config.json {
        eprintln!("info: {message}");
    } else {
        config.style.info(message);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::sync::mpsc;
    use std::time::Duration;

    use anyhow::Result;
    use builderlab_auth::auth_login::{
        AuthMeResponse, AuthMeWorkspace, AuthMeWorkspaces, VerifiedLoginSession,
    };
    use builderlab_auth::auth_storage::{
        SessionCredentialStorage, SessionStorageKey, StoredSessionCredential,
    };

    use builderlab_auth::auth_login::HostedLoginExchangeResponse;

    use super::{
        auth_callback_page, hosted_credential_from_exchange, receive_exchange_code,
        store_login_credential, validate_and_store_login_credential, verify_stored_session_with,
        wait_for_exchange_code, AuthCallbackPage,
    };

    #[test]
    fn callback_wait_times_out_with_retry_guidance() {
        let (_sender, receiver) = mpsc::channel();

        let error = wait_for_exchange_code(&receiver, Duration::ZERO)
            .expect_err("pending login must time out");

        assert_eq!(
            error.to_string(),
            "BuilderLab CLI auth login timed out; rerun `bl auth login`"
        );
    }

    #[test]
    fn callback_wait_reports_stopped_server_without_timeout_guidance() {
        let (sender, receiver) = mpsc::channel();
        drop(sender);

        let error = wait_for_exchange_code(&receiver, Duration::ZERO)
            .expect_err("stopped callback server must fail login");

        assert_eq!(
            error.to_string(),
            "loopback auth server stopped before login completed"
        );
    }

    fn callback_server() -> (String, mpsc::Receiver<Result<String>>) {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("callback server");
        let url = format!("http://{}/callback", server.server_addr());
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = receive_exchange_code(server, "expected-state");
            let _ = sender.send(result);
        });
        (url, receiver)
    }

    #[test]
    fn invalid_state_cannot_complete_or_cancel_pending_login() {
        let (url, receiver) = callback_server();
        let client =
            builderlab_auth::auth_login::build_auth_http_client(std::time::Duration::from_secs(5))
                .expect("client");
        for query in [
            "code=attacker-code",
            "code=attacker-code&state=",
            "code=attacker-code&state=wrong",
            "error=denied&state=wrong",
            "code=attacker-code&state=expected-state&state=wrong",
            "code=attacker-code&state=expected-state&state=expected-state",
        ] {
            let response = client
                .get(format!("{url}?{query}"))
                .send()
                .expect("callback");
            assert_eq!(response.status().as_u16(), 400, "callback query: {query}");
            assert!(response
                .text()
                .expect("failure page")
                .contains("Sign-in didn’t finish"));
            assert!(
                matches!(receiver.try_recv(), Err(mpsc::TryRecvError::Empty)),
                "invalid state must leave the login pending: {query}"
            );
        }
        let response = client
            .get(format!("{url}?code=valid-code&state=expected-state"))
            .send()
            .expect("valid callback");
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            wait_for_exchange_code(&receiver, Duration::from_secs(5)).expect("callback code"),
            "valid-code"
        );
    }

    #[test]
    fn matching_state_rejects_malformed_codes_and_provider_errors() {
        let client =
            builderlab_auth::auth_login::build_auth_http_client(std::time::Duration::from_secs(5))
                .expect("client");
        for (query, expected_error) in [
            ("", "auth callback did not include an exchange code"),
            ("code=", "auth callback did not include an exchange code"),
            (
                "code=one&code=two",
                "auth callback included duplicate exchange codes",
            ),
            (
                "error=private-provider-error&code=one",
                "auth callback returned an authentication error",
            ),
        ] {
            let (url, receiver) = callback_server();
            let response = client
                .get(format!("{url}?state=expected-state&{query}"))
                .send()
                .expect("invalid callback");
            assert_eq!(response.status().as_u16(), 400, "callback query: {query}");
            let error = wait_for_exchange_code(&receiver, Duration::from_secs(5))
                .expect_err("invalid callback");
            // The full error must describe the failure without reflecting provider details.
            assert_eq!(
                format!("{error:#}"),
                expected_error,
                "callback query: {query}"
            );
        }
    }

    struct SwappingStorage {
        reads: RefCell<VecDeque<StoredSessionCredential>>,
        read_count: Cell<usize>,
        writes: RefCell<Vec<StoredSessionCredential>>,
    }

    impl SwappingStorage {
        fn new(reads: impl IntoIterator<Item = StoredSessionCredential>) -> Self {
            Self {
                reads: RefCell::new(reads.into_iter().collect()),
                read_count: Cell::new(0),
                writes: RefCell::new(Vec::new()),
            }
        }
    }

    impl SessionCredentialStorage for SwappingStorage {
        fn kind(&self) -> &'static str {
            "swapping"
        }

        fn get(&self, _key: &SessionStorageKey) -> Result<Option<StoredSessionCredential>> {
            self.read_count.set(self.read_count.get() + 1);
            Ok(self.reads.borrow_mut().pop_front())
        }

        fn set(
            &self,
            _key: &SessionStorageKey,
            credential: &StoredSessionCredential,
        ) -> Result<()> {
            self.writes.borrow_mut().push(credential.clone());
            Ok(())
        }

        fn delete(&self, _key: &SessionStorageKey) -> Result<bool> {
            Ok(false)
        }
    }

    fn stored(value: &str) -> StoredSessionCredential {
        StoredSessionCredential {
            session_credential: value.to_string(),
            expires_at: None,
            ..Default::default()
        }
    }

    fn auth_me() -> AuthMeResponse {
        AuthMeResponse {
            subject: None,
            email: None,
            name: None,
            expires_at: None,
            account_status: None,
            enabled_products: None,
            workspaces: AuthMeWorkspaces {
                active: vec![AuthMeWorkspace {
                    name: "Test Workspace".to_string(),
                }],
            },
        }
    }

    #[test]
    fn verification_returns_the_exact_credential_that_was_checked() {
        let storage = SwappingStorage::new([stored("verified-a"), stored("substituted-b")]);
        let key = SessionStorageKey::new("default", "https://kgoose.example");

        let verified = verify_stored_session_with(&storage, &key, |credential| {
            assert_eq!(credential.session_credential, "verified-a");
            Ok(Some(auth_me()))
        })
        .expect("verify stored session")
        .expect("verified session");

        assert_eq!(verified.credential.session_credential, "verified-a");
        assert_eq!(storage.read_count.get(), 1);
        assert_eq!(
            storage
                .get(&key)
                .expect("read substituted credential")
                .expect("substituted credential")
                .session_credential,
            "substituted-b"
        );
    }

    #[test]
    fn interactive_login_completion_returns_issued_credential_without_rereading_storage() {
        let storage = SwappingStorage::new([stored("substituted-b")]);
        let key = SessionStorageKey::new("default", "https://kgoose.example");

        let returned = store_login_credential(&storage, &key, stored("issued-a"))
            .expect("store completed login");

        assert_eq!(returned.session_credential, "issued-a");
        assert_eq!(storage.read_count.get(), 0);
        assert_eq!(storage.writes.borrow()[0].session_credential, "issued-a");
    }

    #[test]
    fn browser_login_does_not_store_a_session_without_an_active_workspace() {
        let storage = SwappingStorage::new([]);
        let key = SessionStorageKey::new("default", "https://kgoose.example");
        let verified = VerifiedLoginSession {
            credential: stored("issued-without-workspace"),
            me: AuthMeResponse {
                subject: None,
                email: None,
                name: None,
                expires_at: None,
                account_status: None,
                enabled_products: None,
                workspaces: AuthMeWorkspaces { active: vec![] },
            },
        };

        let error = validate_and_store_login_credential(&storage, &key, verified)
            .expect_err("reject login without an active workspace");

        assert!(error.to_string().contains("no active workspaces"));
        assert!(storage.writes.borrow().is_empty());
        assert!(storage.get(&key).expect("read storage").is_none());
    }

    fn hosted_exchange(cookie_domain: &str) -> HostedLoginExchangeResponse {
        HostedLoginExchangeResponse {
            session_credential: "hosted-secret".to_string(),
            cookie_name: "bb_hosted_session".to_string(),
            cookie_domain: cookie_domain.to_string(),
            expires_at: "2099-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn hosted_login_accepts_only_the_expected_cookie_domain() {
        let stored = hosted_credential_from_exchange(
            hosted_exchange(".Apps.Block.Builderlab.xyz"),
            "apps.block.builderlab.xyz",
        )
        .expect("matching cookie domain");
        assert_eq!(stored.session_credential, "hosted-secret");
        assert_eq!(stored.cookie_name.as_deref(), Some("bb_hosted_session"));
        assert_eq!(
            stored.cookie_domain.as_deref(),
            Some("apps.block.builderlab.xyz")
        );
        assert_eq!(stored.expires_at.as_deref(), Some("2099-01-01T00:00:00Z"));

        for cookie_domain in [
            "block.builderlab.xyz",
            "builderlab.xyz",
            "apps.other.builderlab.xyz",
            "evil.example",
        ] {
            let error = hosted_credential_from_exchange(
                hosted_exchange(cookie_domain),
                "apps.block.builderlab.xyz",
            )
            .expect_err("reject a different cookie domain");
            assert!(!format!("{error:#}").contains("hosted-secret"));
        }
    }

    #[test]
    fn hosted_login_rejects_values_that_cannot_be_sent_as_a_cookie() {
        let mut exchange = hosted_exchange("apps.block.builderlab.xyz");
        exchange.cookie_name = "bad name".to_string();
        assert!(hosted_credential_from_exchange(exchange, "apps.block.builderlab.xyz").is_err());

        for value in ["", "a b", "a;b", "a\"b", "a\\b", "a\nb", "a,b"] {
            let mut exchange = hosted_exchange("apps.block.builderlab.xyz");
            exchange.session_credential = value.to_string();
            assert!(
                hosted_credential_from_exchange(exchange, "apps.block.builderlab.xyz").is_err(),
                "credential {value:?}"
            );
        }
    }

    #[test]
    fn callback_pages_are_self_contained_and_themed() {
        for page in [AuthCallbackPage::Success, AuthCallbackPage::Failure] {
            let html = auth_callback_page(page);

            assert!(html.starts_with("<!doctype html>"));
            assert!(html.contains("prefers-color-scheme: dark"));
            assert!(html.contains("prefers-reduced-motion: no-preference"));
            assert!(html.contains(">Berd</div>"));
            assert!(!html.contains("src="));
            assert!(!html.contains("href="));
            assert!(!html.contains("@import"));
            assert!(!html.contains("__PAGE_"));
            assert!(!html.contains("__STATUS_"));
            assert!(!html.contains("__HEADING__"));
            assert!(!html.contains("__MESSAGE__"));
            assert!(!html.contains("__TERMINAL_"));
        }
    }

    #[test]
    fn callback_pages_have_distinct_outcomes() {
        let success = auth_callback_page(AuthCallbackPage::Success);
        let failure = auth_callback_page(AuthCallbackPage::Failure);

        assert!(success.contains("You’re signed in"));
        assert!(success.contains(r#"class="success""#));
        assert!(failure.contains("Sign-in didn’t finish"));
        assert!(failure.contains(r#"class="failure""#));
    }
}
