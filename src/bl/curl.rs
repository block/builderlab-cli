//! `bl curl`: call a protected BuilderLab hosted app with the system `curl`.
//!
//! Hosted apps accept only the tenant's hosted-site session cookie. This
//! command obtains a `cli_hosted` session through the browser login, stores it
//! apart from the CLI session, and hands it to `curl` as that cookie.
//!
//! The cookie is sent only to HTTPS hosts inside the configured tenant's
//! hosted-app domain, and only through `curl --config -` on stdin, so it never
//! appears on the command line. Options that would print it, send it to
//! another host, or read the request from stdin are refused.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use builderlab_auth::auth_storage::StoredSessionCredential;
use clap::{Arg, ArgMatches, Command};
use serde_json::json;
use url::{Host, Url};

use super::auth_login::{is_cookie_name, is_cookie_value, run_hosted_browser_login};
use super::auth_storage::{default_session_storage, hosted_session_storage_key};
use super::display::terminal_safe_text;
use super::runner;
use super::skills_api::{exit_codes, failure, CliFailure, SilentJsonExit};
use super::skills_config::SkillsConfig;

/// BuilderLab domains that serve tenant hosted apps at
/// `<app>.apps.<tenant>.<root>`.
const HOSTED_APP_ROOT_DOMAINS: &[&str] = &["builderlab.xyz", "builderlabstaging.xyz"];
const COMPOSE_SERVER_ACTION_PREFIX: &str = "/_compose/server/";
const CONSENT_URL_HEADER: &str = "x-bb-consent-url";
/// Methods `bl curl` resends after logging in again. Others may have side
/// effects, and the app itself can answer 401 after acting on a request.
const SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];
/// How much of a response body `bl curl` keeps to look for a consent error.
const BODY_CAPTURE_LIMIT: usize = 64 * 1024;
const FILE_TIME_SLACK: std::time::Duration = std::time::Duration::from_secs(1);
// Treat a session this close to expiry as expired instead of racing it.
const EXPIRY_SKEW_SECS: i64 = 60;

const ABOUT: &str = "Call a protected BuilderLab hosted app with curl";
const LONG_ABOUT: &str = "\
Call a protected BuilderLab hosted app with the system curl.

The URL must be the first argument and must be an https URL on a hosted app
of the configured org (https://<app>.apps.<org>.builderlab.xyz/...). The
remaining arguments are passed to curl.

On first use, or when the stored hosted-app session has expired, this opens a
browser login (type=cli_hosted) and stores the session apart from the
`bl auth login` session. The session cookie is passed to curl on stdin, never
on the command line. POST requests to /_compose/server/* get
`Origin: https://<host>` unless you set Origin yourself.

Options that could print or leak the session cookie or read the request from
stdin are refused: for example -v, --trace, -L, -b, -c, -K, -k, -u, and
-d @-. So are --no-globoff, --no-disable, --no-get, and --no-head. bl curl
reads response headers itself, so use -i instead of -D.

If an app needs your approval first, bl curl prints the approval URL and
exits with code 3.

If the app rejects the stored session, bl curl logs in again once. It resends
only GET, HEAD, and OPTIONS requests; for other methods it exits with code 3
so you can rerun the command with the new session.

Examples:
  bl curl https://myapp.apps.block.builderlab.xyz/api/items
  bl curl https://myapp.apps.block.builderlab.xyz/_compose/server/save \\
    -H 'Content-Type: application/json' -d '{\"name\":\"x\"}'";

pub fn command() -> Command {
    Command::new("curl")
        .about(ABOUT)
        .long_about(LONG_ABOUT)
        .arg(
            Arg::new("url")
                .value_name("URL")
                .required(true)
                .help("https URL of a hosted app in the configured org"),
        )
        .arg(
            Arg::new("curl-args")
                .value_name("CURL_OPTIONS")
                .num_args(0..)
                .trailing_var_arg(true)
                .allow_hyphen_values(true)
                .help("Options passed to curl"),
        )
}

pub fn describe_commands() -> serde_json::Value {
    json!({ "name": "curl", "summary": ABOUT })
}

pub fn run(matches: &ArgMatches) -> Result<()> {
    let config = SkillsConfig::resolve(matches)?;
    let mut exit_code = 0;
    runner::run_with_output(config.json, || {
        exit_code = dispatch(&config, matches)?;
        Ok(())
    })?;
    if exit_code == 0 {
        Ok(())
    } else {
        // curl already reported its own failure; exit with its code.
        Err(anyhow::Error::new(SilentJsonExit(exit_code)))
    }
}

fn dispatch(config: &SkillsConfig, matches: &ArgMatches) -> Result<i32> {
    let url = matches.get_one::<String>("url").context("expected a URL")?;
    let curl_args = matches
        .get_many::<String>("curl-args")
        .map(|values| values.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let org = config.org.as_deref().ok_or_else(|| {
        failure(
            exit_codes::AUTH_REQUIRED,
            "org_required",
            "bl org is not configured; run `bl config set org <org>`",
        )
    })?;
    let target = resolve_hosted_target(url, org)?;
    let request = CurlRequest::new(target, &curl_args)?;
    let storage = default_session_storage(config)?;
    let sessions = StoredHostedSessions {
        config,
        storage: storage.as_ref(),
        hosted_domain: request.target.hosted_domain.clone(),
    };
    run_request(&sessions, &SystemCurl, &request)
}

// ---------------------------------------------------------------------------
// tenant and host validation

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedTarget {
    pub url: Url,
    pub host: String,
    /// The tenant's hosted-app cookie domain, e.g. `apps.block.builderlab.xyz`.
    pub hosted_domain: String,
}

/// Hosted-app domains a tenant can have, one per BuilderLab root domain.
pub fn hosted_app_domains_for_org(org: &str) -> Vec<String> {
    HOSTED_APP_ROOT_DOMAINS
        .iter()
        .map(|root| format!("apps.{org}.{root}"))
        .collect()
}

pub fn resolve_hosted_target(raw_url: &str, org: &str) -> Result<HostedTarget> {
    let usage = |message: String| failure(exit_codes::GENERAL, "invalid_hosted_app_url", message);
    let shown = terminal_safe_text(raw_url);
    let url = Url::parse(raw_url).map_err(|_| {
        usage(format!(
            "`{shown}` is not a URL; usage: bl curl <url> [curl options...]"
        ))
    })?;
    if url.scheme() != "https" {
        return Err(usage(format!(
            "bl curl only calls https URLs, not `{shown}`"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(usage(
            "bl curl URLs must not include a username or password".to_string(),
        ));
    }
    if url.port().is_some() {
        return Err(usage(
            "bl curl URLs must use the default https port".to_string(),
        ));
    }
    let host = match url.host() {
        Some(Host::Domain(host)) => host.to_ascii_lowercase(),
        _ => {
            return Err(usage(format!(
                "`{shown}` is not a BuilderLab hosted-app URL"
            )))
        }
    };

    let tenant = HOSTED_APP_ROOT_DOMAINS.iter().find_map(|root| {
        let prefix = host.strip_suffix(&format!(".{root}"))?;
        let mut labels = prefix.rsplit('.');
        let tenant = labels.next()?;
        let apps = labels.next()?;
        let app_labels = labels.collect::<Vec<_>>();
        let valid = apps == "apps"
            && !tenant.is_empty()
            && !app_labels.is_empty()
            && app_labels.iter().all(|label| !label.is_empty());
        valid.then(|| (tenant.to_string(), format!("apps.{tenant}.{root}")))
    });
    let Some((tenant, hosted_domain)) = tenant else {
        return Err(usage(format!(
            "`{}` is not a BuilderLab hosted app; bl curl only sends the hosted-app session to https://<app>.apps.{org}.builderlab.xyz",
            terminal_safe_text(&host)
        )));
    };
    if tenant != org {
        return Err(failure(
            exit_codes::GENERAL,
            "hosted_app_tenant_mismatch",
            format!(
                "`{}` is a hosted app of org `{}`, but bl is configured for org `{org}`; run `bl config set org {}` to call it",
                terminal_safe_text(&host),
                terminal_safe_text(&tenant),
                terminal_safe_text(&tenant)
            ),
        ));
    }
    Ok(HostedTarget {
        url,
        host,
        hosted_domain,
    })
}

fn domain_matches(host: &str, cookie_domain: &str) -> bool {
    let cookie_domain = cookie_domain.trim_start_matches('.');
    !cookie_domain.is_empty()
        && (host == cookie_domain || host.ends_with(&format!(".{cookie_domain}")))
}

// ---------------------------------------------------------------------------
// curl argument checks

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Plain,
    Method,
    Header,
    Data,
    DataRaw,
    DataUrlencode,
    Json,
    Form,
    FormString,
    Get,
    Head,
    Upload,
    Output,
    OutputDir,
}

struct CurlOption {
    long: &'static str,
    short: Option<char>,
    takes_value: bool,
    role: Role,
}

const fn flag(long: &'static str, short: Option<char>, role: Role) -> CurlOption {
    CurlOption {
        long,
        short,
        takes_value: false,
        role,
    }
}

const fn value(long: &'static str, short: Option<char>, role: Role) -> CurlOption {
    CurlOption {
        long,
        short,
        takes_value: true,
        role,
    }
}

/// curl options `bl curl` passes through. Anything else is refused, so the
/// URL and option values are always parsed the way curl will parse them.
const ALLOWED_OPTIONS: &[CurlOption] = &[
    flag("silent", Some('s'), Role::Plain),
    flag("show-error", Some('S'), Role::Plain),
    flag("fail", Some('f'), Role::Plain),
    flag("fail-with-body", None, Role::Plain),
    flag("include", Some('i'), Role::Plain),
    flag("head", Some('I'), Role::Head),
    flag("get", Some('G'), Role::Get),
    flag("no-buffer", Some('N'), Role::Plain),
    flag("compressed", None, Role::Plain),
    flag("progress-bar", Some('#'), Role::Plain),
    flag("no-progress-meter", None, Role::Plain),
    flag("remote-name", Some('O'), Role::Plain),
    flag("remote-header-name", Some('J'), Role::Plain),
    flag("remote-time", Some('R'), Role::Plain),
    flag("create-dirs", None, Role::Plain),
    flag("globoff", Some('g'), Role::Plain),
    flag("http1.1", None, Role::Plain),
    flag("http2", None, Role::Plain),
    flag("retry-all-errors", None, Role::Plain),
    flag("retry-connrefused", None, Role::Plain),
    value("request", Some('X'), Role::Method),
    value("header", Some('H'), Role::Header),
    value("data", Some('d'), Role::Data),
    value("data-ascii", None, Role::Data),
    value("data-binary", None, Role::Data),
    value("data-raw", None, Role::DataRaw),
    value("data-urlencode", None, Role::DataUrlencode),
    value("json", None, Role::Json),
    value("form", Some('F'), Role::Form),
    value("form-string", None, Role::FormString),
    value("upload-file", Some('T'), Role::Upload),
    value("url-query", None, Role::Plain),
    value("output", Some('o'), Role::Output),
    value("output-dir", None, Role::OutputDir),
    value("user-agent", Some('A'), Role::Plain),
    value("referer", Some('e'), Role::Plain),
    value("range", Some('r'), Role::Plain),
    value("time-cond", Some('z'), Role::Plain),
    value("continue-at", Some('C'), Role::Plain),
    value("write-out", Some('w'), Role::Plain),
    value("max-time", Some('m'), Role::Plain),
    value("connect-timeout", None, Role::Plain),
    value("expect100-timeout", None, Role::Plain),
    value("retry", None, Role::Plain),
    value("retry-delay", None, Role::Plain),
    value("retry-max-time", None, Role::Plain),
    value("limit-rate", None, Role::Plain),
    value("max-filesize", None, Role::Plain),
    value("stderr", None, Role::Plain),
];

/// Refused options with the reason shown to the caller.
const REFUSED_OPTIONS: &[(&str, Option<char>, &str)] = &[
    ("verbose", Some('v'), "it would print the session cookie"),
    ("trace", None, "it would print the session cookie"),
    ("trace-ascii", None, "it would print the session cookie"),
    ("trace-config", None, "it would print the session cookie"),
    (
        "libcurl",
        None,
        "it would write the session cookie into generated code",
    ),
    (
        "config",
        Some('K'),
        "bl curl passes its own config on stdin",
    ),
    ("disable", Some('q'), "bl curl already ignores .curlrc"),
    ("no-disable", None, "bl curl must keep ignoring .curlrc"),
    ("next", Some(':'), "bl curl sends exactly one request"),
    (
        "no-globoff",
        None,
        "bl curl keeps URL globbing off so one URL cannot become several requests",
    ),
    ("no-get", None, "bl curl must know the request method"),
    ("no-head", None, "bl curl must know the request method"),
    ("url", None, "pass the URL as the first argument"),
    (
        "location",
        Some('L'),
        "a redirect could carry the session cookie to another host",
    ),
    (
        "location-trusted",
        None,
        "a redirect could carry the session cookie to another host",
    ),
    (
        "cookie",
        Some('b'),
        "bl curl sends the hosted-app session cookie itself",
    ),
    (
        "cookie-jar",
        Some('c'),
        "it would write the session cookie to a file",
    ),
    (
        "junk-session-cookies",
        Some('j'),
        "bl curl sends the hosted-app session cookie itself",
    ),
    (
        "dump-header",
        Some('D'),
        "bl curl reads response headers itself; use -i to include them in the output",
    ),
    (
        "insecure",
        Some('k'),
        "it could send the session cookie to an unverified host",
    ),
    (
        "resolve",
        None,
        "it could send the session cookie to another host",
    ),
    (
        "connect-to",
        None,
        "it could send the session cookie to another host",
    ),
    (
        "user",
        Some('u'),
        "hosted apps accept only the session cookie",
    ),
    (
        "oauth2-bearer",
        None,
        "hosted apps accept only the session cookie",
    ),
    (
        "netrc",
        Some('n'),
        "hosted apps accept only the session cookie",
    ),
    (
        "netrc-file",
        None,
        "hosted apps accept only the session cookie",
    ),
    (
        "netrc-optional",
        None,
        "hosted apps accept only the session cookie",
    ),
];

/// Request headers `bl curl` owns or that hosted apps reject.
const REFUSED_HEADERS: &[&str] = &["cookie", "authorization", "x-bb-session-credential"];

#[derive(Debug)]
pub struct CurlRequest {
    pub target: HostedTarget,
    pub user_args: Vec<String>,
    pub method: String,
    pub user_sets_origin: bool,
    /// File curl writes the response body to, if `-o` names one.
    pub output_file: Option<PathBuf>,
}

impl CurlRequest {
    pub fn new(target: HostedTarget, args: &[String]) -> Result<Self> {
        let mut method = None;
        let mut user_sets_origin = false;
        let (mut output, mut output_dir) = (None, None);
        let (mut get, mut head, mut upload, mut body) = (false, false, false, false);

        let mut handle = |role: Role, option: &str, value: Option<&str>| -> Result<()> {
            let value = value.unwrap_or_default();
            match role {
                Role::Plain => {}
                Role::DataRaw | Role::FormString => body = true,
                Role::Method => method = Some(value.to_ascii_uppercase()),
                Role::Header => {
                    if value.starts_with('@') {
                        return Err(refused(
                            option,
                            "bl curl cannot check headers read from a file",
                        ));
                    }
                    let name = value
                        .split([':', ';'])
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_ascii_lowercase();
                    if REFUSED_HEADERS.contains(&name.as_str()) {
                        return Err(refused(
                            &format!("{option} {name}"),
                            "hosted apps accept only the session cookie that bl curl sends",
                        ));
                    }
                    if name == "origin" {
                        user_sets_origin = true;
                    }
                }
                Role::Data | Role::Json => {
                    if value == "@-" {
                        return Err(stdin_refused(option));
                    }
                    body = true;
                }
                Role::DataUrlencode => {
                    if value.ends_with("@-") {
                        return Err(stdin_refused(option));
                    }
                    body = true;
                }
                Role::Form => {
                    if value.contains("=@-") || value.contains("=<-") {
                        return Err(stdin_refused(option));
                    }
                    body = true;
                }
                Role::Output => output = Some(value.to_string()),
                Role::OutputDir => output_dir = Some(value.to_string()),
                Role::Get => get = true,
                Role::Head => head = true,
                Role::Upload => {
                    if value == "-" || value == "." {
                        return Err(stdin_refused(option));
                    }
                    upload = true;
                }
            }
            Ok(())
        };

        let mut index = 0;
        while index < args.len() {
            let arg = args[index].as_str();
            index += 1;
            if let Some(name) = arg.strip_prefix("--").filter(|name| !name.is_empty()) {
                if let Some((_, _, reason)) =
                    REFUSED_OPTIONS.iter().find(|(long, ..)| *long == name)
                {
                    return Err(refused(arg, reason));
                }
                let option = ALLOWED_OPTIONS
                    .iter()
                    .find(|option| option.long == name)
                    .or_else(|| {
                        // curl accepts --no-<flag> to turn a boolean off. Allow
                        // it only for flags that do not change the request or
                        // undo an option bl curl enforces.
                        name.strip_prefix("no-").and_then(|name| {
                            ALLOWED_OPTIONS.iter().find(|option| {
                                option.long == name
                                    && !option.takes_value
                                    && option.role == Role::Plain
                                    && option.long != "globoff"
                            })
                        })
                    })
                    .ok_or_else(|| unsupported(arg))?;
                if option.takes_value {
                    let value = args.get(index).ok_or_else(|| missing_value(arg))?;
                    index += 1;
                    handle(option.role, arg, Some(value))?;
                } else if !name.starts_with("no-") {
                    handle(option.role, arg, None)?;
                }
            } else if let Some(cluster) = arg.strip_prefix('-').filter(|rest| !rest.is_empty()) {
                for (offset, short) in cluster.char_indices() {
                    let shown = format!("-{short}");
                    if let Some((_, _, reason)) = REFUSED_OPTIONS
                        .iter()
                        .find(|(_, refused_short, _)| *refused_short == Some(short))
                    {
                        return Err(refused(&shown, reason));
                    }
                    let option = ALLOWED_OPTIONS
                        .iter()
                        .find(|option| option.short == Some(short))
                        .ok_or_else(|| unsupported(&shown))?;
                    if !option.takes_value {
                        handle(option.role, &shown, None)?;
                        continue;
                    }
                    let attached = &cluster[offset + short.len_utf8()..];
                    let value = if attached.is_empty() {
                        let value = args.get(index).ok_or_else(|| missing_value(&shown))?;
                        index += 1;
                        value.as_str()
                    } else {
                        attached
                    };
                    handle(option.role, &shown, Some(value))?;
                    break;
                }
            } else {
                return Err(failure(
                    exit_codes::GENERAL,
                    "unsupported_curl_argument",
                    format!(
                        "bl curl sends one request; pass a single URL as the first argument, not `{}`",
                        terminal_safe_text(arg)
                    ),
                ));
            }
        }

        let method = method.unwrap_or_else(|| {
            if head {
                "HEAD"
            } else if upload {
                "PUT"
            } else if body && !get {
                "POST"
            } else {
                "GET"
            }
            .to_string()
        });
        let output_file = output
            .filter(|output| output != "-")
            .map(|output| match output_dir {
                Some(directory) if Path::new(&output).is_relative() => {
                    Path::new(&directory).join(output)
                }
                _ => PathBuf::from(output),
            });
        Ok(Self {
            target,
            user_args: args.to_vec(),
            method,
            user_sets_origin,
            output_file,
        })
    }

    /// Whether the request can be resent without repeating a side effect.
    pub fn is_safe_method(&self) -> bool {
        SAFE_METHODS.contains(&self.method.as_str())
    }

    /// Origin header to add for a Compose server action, if any.
    pub fn added_origin(&self) -> Option<String> {
        (self.method == "POST"
            && self
                .target
                .url
                .path()
                .starts_with(COMPOSE_SERVER_ACTION_PREFIX)
            && !self.user_sets_origin)
            .then(|| format!("https://{}", self.target.host))
    }

    /// Arguments for curl after the program name. The session never appears
    /// here; it goes in [`Self::stdin_config`].
    pub fn argv(&self) -> Vec<String> {
        // -q must come first so ~/.curlrc cannot add options; --globoff stops
        // curl from expanding the URL into several URLs.
        let mut argv = vec![
            "-q".to_string(),
            "--config".to_string(),
            "-".to_string(),
            "--globoff".to_string(),
            self.target.url.as_str().to_string(),
        ];
        argv.extend(self.user_args.iter().cloned());
        argv
    }

    /// curl config read from stdin: the session cookie, an added Origin, and
    /// where to write the response headers.
    pub fn stdin_config(
        &self,
        session: &StoredSessionCredential,
        header_file: &Path,
    ) -> Result<String> {
        let cookie_name = session.cookie_name.as_deref().unwrap_or_default();
        let credential = session.session_credential.as_str();
        if !is_cookie_name(cookie_name) || !is_cookie_value(credential) {
            return Err(anyhow!("stored hosted-app session is invalid"));
        }
        let mut config = format!(
            "cookie = {}\n",
            config_string(&format!("{cookie_name}={credential}"))?
        );
        if let Some(origin) = self.added_origin() {
            config.push_str(&format!(
                "header = {}\n",
                config_string(&format!("Origin: {origin}"))?
            ));
        }
        let header_file = header_file
            .to_str()
            .ok_or_else(|| anyhow!("temporary header file path is not UTF-8"))?;
        config.push_str(&format!("dump-header = {}\n", config_string(header_file)?));
        Ok(config)
    }
}

fn config_string(value: &str) -> Result<String> {
    if value.chars().any(char::is_control) {
        return Err(anyhow!("curl config value contains a control character"));
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn refused(option: &str, reason: &str) -> anyhow::Error {
    failure(
        exit_codes::GENERAL,
        "unsupported_curl_argument",
        format!(
            "bl curl does not allow `{}`: {reason}",
            terminal_safe_text(option)
        ),
    )
}

fn stdin_refused(option: &str) -> anyhow::Error {
    refused(
        option,
        "bl curl uses stdin to pass the session to curl; read request data from a file instead",
    )
}

fn unsupported(option: &str) -> anyhow::Error {
    failure(
        exit_codes::GENERAL,
        "unsupported_curl_argument",
        format!(
            "bl curl does not support the curl option `{}`",
            terminal_safe_text(option)
        ),
    )
}

fn missing_value(option: &str) -> anyhow::Error {
    failure(
        exit_codes::GENERAL,
        "unsupported_curl_argument",
        format!("curl option `{}` needs a value", terminal_safe_text(option)),
    )
}

// ---------------------------------------------------------------------------
// sessions

pub trait HostedSessions {
    /// The stored session, if any.
    fn stored(&self) -> Result<Option<StoredSessionCredential>>;
    /// Run the browser login and store the new session.
    fn login(&self) -> Result<StoredSessionCredential>;
    /// Forget the stored session.
    fn forget(&self) -> Result<()>;
}

struct StoredHostedSessions<'a> {
    config: &'a SkillsConfig,
    storage: &'a dyn builderlab_auth::auth_storage::SessionCredentialStorage,
    hosted_domain: String,
}

impl HostedSessions for StoredHostedSessions<'_> {
    fn stored(&self) -> Result<Option<StoredSessionCredential>> {
        self.storage.get(&hosted_session_storage_key(
            self.config,
            &self.hosted_domain,
        ))
    }

    fn login(&self) -> Result<StoredSessionCredential> {
        run_hosted_browser_login(self.config, self.storage, &self.hosted_domain)
    }

    fn forget(&self) -> Result<()> {
        self.storage
            .delete(&hosted_session_storage_key(
                self.config,
                &self.hosted_domain,
            ))
            .map(|_| ())
    }
}

fn usable_session(
    session: StoredSessionCredential,
    target: &HostedTarget,
    now: i64,
) -> Option<StoredSessionCredential> {
    let cookie_domain = session.cookie_domain.as_deref()?;
    if cookie_domain != target.hosted_domain || !domain_matches(&target.host, cookie_domain) {
        return None;
    }
    session.cookie_name.as_deref()?;
    let expired = session
        .expires_at
        .as_deref()
        .and_then(parse_rfc3339_utc)
        .is_some_and(|expires_at| expires_at <= now + EXPIRY_SKEW_SECS);
    (!expired).then_some(session)
}

/// Seconds since the Unix epoch for an RFC 3339 timestamp.
fn parse_rfc3339_utc(value: &str) -> Option<i64> {
    let value = value.trim();
    let (date, rest) = value.split_once(['T', 't', ' '])?;
    let mut date_parts = date.splitn(3, '-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    let offset_at = rest.find(['Z', 'z', '+', '-'])?;
    let (time, offset) = rest.split_at(offset_at);
    let mut time_parts = time.splitn(3, ':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.split('.').next()?.parse().ok()?;
    let offset_secs = match offset {
        "Z" | "z" => 0,
        _ => {
            let sign = if offset.starts_with('-') { -1 } else { 1 };
            let (hours, minutes) = offset[1..].split_once(':')?;
            sign * (hours.parse::<i64>().ok()? * 3600 + minutes.parse::<i64>().ok()? * 60)
        }
    };
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    // Days from civil, Howard Hinnant's algorithm.
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year.div_euclid(400);
    let year_of_era = shifted_year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// running curl

/// Final response status and the headers `bl curl` acts on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub www_authenticate: Vec<String>,
    pub consent_url: Option<String>,
}

impl ResponseHead {
    fn consent_required(&self) -> bool {
        self.status == 401 && self.consent_url.is_some()
    }

    /// 401 because the hosted-app session is missing or invalid.
    pub fn session_rejected(&self) -> bool {
        self.status == 401
            && self.consent_url.is_none()
            && self.www_authenticate.iter().any(|value| {
                value
                    .split_whitespace()
                    .next()
                    .is_some_and(|scheme| scheme.eq_ignore_ascii_case("BBIdentity"))
            })
    }
}

pub struct CurlOutcome {
    pub exit_code: i32,
    pub response: Option<ResponseHead>,
    /// Start of what curl wrote to stdout, up to `BODY_CAPTURE_LIMIT` bytes.
    pub output_prefix: Vec<u8>,
}

pub trait CurlRunner {
    /// Run curl with `argv` and `stdin_config`. With `hold_rejected_output`,
    /// output of a response that rejects the session is discarded so the
    /// request can be resent without duplicate output.
    fn run(
        &self,
        argv: &[String],
        stdin_config: &dyn Fn(&Path) -> Result<String>,
        hold_rejected_output: bool,
    ) -> Result<CurlOutcome>;
}

/// Run the request, logging in first when no usable session is stored and
/// once more if the hosted app rejects a stored session. Only safe methods
/// are resent after that login. Returns curl's exit code.
pub fn run_request(
    sessions: &dyn HostedSessions,
    curl: &dyn CurlRunner,
    request: &CurlRequest,
) -> Result<i32> {
    let stored = sessions
        .stored()?
        .and_then(|session| usable_session(session, &request.target, now_unix()));
    let from_storage = stored.is_some();
    let session = match stored {
        Some(session) => session,
        None => sessions.login()?,
    };
    let resend = request.is_safe_method();

    let mut outcome = run_once(curl, request, &session, from_storage && resend)?;
    if from_storage
        && outcome
            .response
            .as_ref()
            .is_some_and(ResponseHead::session_rejected)
    {
        eprintln!("info: The stored BuilderLab hosted-app session was rejected; logging in again");
        sessions.forget()?;
        let session = sessions.login()?;
        if !resend {
            return Err(failure(
                exit_codes::AUTH_REQUIRED,
                "hosted_session_refreshed",
                format!(
                    "{} rejected the stored BuilderLab hosted-app session. bl curl logged in again but did not resend the {} request, because repeating it could repeat its effect. Rerun the command to send it with the new session.",
                    request.target.host, request.method
                ),
            ));
        }
        outcome = run_once(curl, request, &session, false)?;
    }

    match outcome.response {
        Some(response) if response.consent_required() => Err(consent_required(
            &request.target.host,
            response.consent_url.as_deref().unwrap_or_default(),
        )),
        Some(response) if response.session_rejected() => Err(failure(
            exit_codes::AUTH_REQUIRED,
            "hosted_session_rejected",
            format!(
                "{} rejected a new BuilderLab hosted-app session; check that bl is configured for the right org and backend",
                request.target.host
            ),
        )),
        _ => Ok(outcome.exit_code),
    }
}

fn run_once(
    curl: &dyn CurlRunner,
    request: &CurlRequest,
    session: &StoredSessionCredential,
    hold_rejected_output: bool,
) -> Result<CurlOutcome> {
    let cookie_domain = session.cookie_domain.as_deref().unwrap_or_default();
    if cookie_domain != request.target.hosted_domain
        || !domain_matches(&request.target.host, cookie_domain)
    {
        return Err(anyhow!(
            "the hosted-app session is not valid for {}",
            request.target.host
        ));
    }
    let started = SystemTime::now();
    let mut outcome = curl.run(
        &request.argv(),
        &|header_file| request.stdin_config(session, header_file),
        hold_rejected_output,
    )?;
    // Ingress may drop X-BB-Consent-Url; the JSON error body still says so.
    if let Some(response) = outcome
        .response
        .as_mut()
        .filter(|response| response.status == 401 && response.consent_url.is_none())
    {
        response.consent_url = consent_url_from_body(&outcome.output_prefix).or_else(|| {
            let output_file = request.output_file.as_deref()?;
            consent_url_from_body(&read_fresh_prefix(output_file, started)?)
        });
    }
    Ok(outcome)
}

/// `approval_url` from a `{"error":"consent_required",...}` body. With `-i`
/// the response headers come first, so also try what follows them.
fn consent_url_from_body(output: &[u8]) -> Option<String> {
    let parse = |body: &[u8]| -> Option<String> {
        let value: serde_json::Value = serde_json::from_slice(body).ok()?;
        if value.get("error")?.as_str()? != "consent_required" {
            return None;
        }
        value.get("approval_url")?.as_str().map(str::to_string)
    };
    parse(output).or_else(|| {
        let body_start = output
            .windows(4)
            .rposition(|window| window == b"\r\n\r\n")?
            + 4;
        parse(&output[body_start..])
    })
}

/// The start of `path`, if curl wrote it during this run.
fn read_fresh_prefix(path: &Path, started: SystemTime) -> Option<Vec<u8>> {
    let file = File::open(path).ok()?;
    let modified = file.metadata().ok()?.modified().ok()?;
    // File timestamps come from a coarse clock and can trail `started`.
    if modified < started.checked_sub(FILE_TIME_SLACK)? {
        return None;
    }
    let mut prefix = Vec::new();
    file.take(BODY_CAPTURE_LIMIT as u64)
        .read_to_end(&mut prefix)
        .ok()?;
    Some(prefix)
}

fn consent_required(host: &str, approval_url: &str) -> anyhow::Error {
    let approval_url = Url::parse(approval_url)
        .ok()
        .filter(|url| url.scheme() == "https")
        .map(|url| url.to_string());
    let message = match &approval_url {
        Some(url) => format!(
            "{host} needs your approval before bl curl can call it. Open this URL to approve, then rerun the command:\n  {}",
            terminal_safe_text(url)
        ),
        None => format!(
            "{host} needs your approval before bl curl can call it, but did not return a valid approval URL"
        ),
    };
    let mut failure = CliFailure::new(exit_codes::AUTH_REQUIRED, "consent_required", message);
    if let Some(url) = approval_url {
        failure.details = Some(json!({ "approval_url": url }));
    }
    anyhow::Error::new(failure)
}

/// Runs the `curl` found on PATH.
pub struct SystemCurl;

impl CurlRunner for SystemCurl {
    fn run(
        &self,
        argv: &[String],
        stdin_config: &dyn Fn(&Path) -> Result<String>,
        hold_rejected_output: bool,
    ) -> Result<CurlOutcome> {
        let header_file = TempFile::create()?;
        let config = stdin_config(header_file.path())?;
        let mut child = ProcessCommand::new("curl")
            .args(argv)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            // Never let curl log TLS secrets for this request.
            .env_remove("SSLKEYLOGFILE")
            .spawn()
            .map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => anyhow!("bl curl needs `curl` on PATH"),
                _ => anyhow!("start curl: {error}"),
            })?;
        {
            let mut stdin = child.stdin.take().context("open curl stdin")?;
            stdin
                .write_all(config.as_bytes())
                .context("pass config to curl")?;
        }
        let stdout = child.stdout.take().context("open curl stdout")?;
        let output_prefix = forward_output(
            stdout,
            &mut io::stdout().lock(),
            header_file.path(),
            hold_rejected_output,
        )?;
        let status = child.wait().context("wait for curl")?;
        let response = read_response_head(header_file.path());
        Ok(CurlOutcome {
            exit_code: status.code().unwrap_or(exit_codes::GENERAL),
            response,
            output_prefix,
        })
    }
}

/// Copy curl's output to `sink` and return its first `BODY_CAPTURE_LIMIT`
/// bytes.
///
/// With `hold_rejected`, the output of a response that rejects the session is
/// withheld so the request can be resent without duplicate output. curl
/// flushes each response header to the `--dump-header` file as it arrives,
/// so once body bytes reach stdout the final status is known; output is held
/// only until then. A rejection whose body is a consent error is still shown.
fn forward_output(
    mut source: impl Read,
    sink: &mut impl Write,
    header_file: &Path,
    hold_rejected: bool,
) -> Result<Vec<u8>> {
    #[derive(PartialEq)]
    enum State {
        Undecided,
        Forward,
        Withhold,
        Discard,
    }
    let rejected = |held: &[u8]| {
        read_response_head(header_file).is_some_and(|head| head.session_rejected())
            && consent_url_from_body(held).is_none()
    };

    let mut state = if hold_rejected {
        State::Undecided
    } else {
        State::Forward
    };
    let mut captured = Vec::new();
    let mut held = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = source.read(&mut chunk).context("read curl output")?;
        if read == 0 {
            break;
        }
        let chunk = &chunk[..read];
        let room = BODY_CAPTURE_LIMIT.saturating_sub(captured.len());
        captured.extend_from_slice(&chunk[..room.min(read)]);
        match state {
            State::Forward => sink.write_all(chunk).context("write output")?,
            State::Discard => {}
            State::Undecided | State::Withhold => {
                held.extend_from_slice(chunk);
                if state == State::Undecided {
                    if let Some(head) = read_response_head(header_file) {
                        if head.session_rejected() {
                            state = State::Withhold;
                        } else {
                            sink.write_all(&held).context("write output")?;
                            held.clear();
                            state = State::Forward;
                        }
                    }
                }
                // Too long to be a consent error: drop the rejected output.
                if state == State::Withhold && held.len() > BODY_CAPTURE_LIMIT {
                    held.clear();
                    state = State::Discard;
                }
            }
        }
    }
    if matches!(state, State::Undecided | State::Withhold) && !rejected(&held) {
        sink.write_all(&held).context("write output")?;
    }
    sink.flush().context("flush output")?;
    Ok(captured)
}

fn read_response_head(header_file: &Path) -> Option<ResponseHead> {
    let bytes = fs::read(header_file).ok()?;
    parse_response_head(&String::from_utf8_lossy(&bytes))
}

/// Parse the last complete, final (non-1xx) response in a `--dump-header`
/// file.
pub fn parse_response_head(text: &str) -> Option<ResponseHead> {
    let mut last = None;
    let mut current: Option<ResponseHead> = None;
    // Ignore a trailing partial line that curl has not finished writing.
    for line in text
        .split_inclusive('\n')
        .filter(|line| line.ends_with('\n'))
    {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.starts_with("HTTP/") {
            current = line
                .split_whitespace()
                .nth(1)
                .and_then(|status| status.parse().ok())
                .map(|status| ResponseHead {
                    status,
                    ..ResponseHead::default()
                });
        } else if line.is_empty() {
            if let Some(head) = current.take() {
                if head.status >= 200 {
                    last = Some(head);
                }
            }
        } else if let (Some(head), Some((name, value))) = (current.as_mut(), line.split_once(':')) {
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("www-authenticate") {
                head.www_authenticate.push(value);
            } else if name.eq_ignore_ascii_case(CONSENT_URL_HEADER) {
                head.consent_url = Some(value);
            }
        }
    }
    last
}

/// A private temporary file removed on drop.
struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn create() -> Result<Self> {
        let directory = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        for attempt in 0..16 {
            let path = directory.join(format!(
                "bl-curl-{}-{nanos}-{attempt}.headers",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    drop::<File>(file);
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error).context("create temporary header file"),
            }
        }
        Err(anyhow!("create temporary header file"))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    use super::*;
    use crate::bl::skills_api::failure_info;

    const SECRET: &str = "hosted-secret-credential-123";
    const APP_URL: &str = "https://myapp.apps.block.builderlab.xyz/api/items";
    const ACTION_URL: &str = "https://myapp.apps.block.builderlab.xyz/_compose/server/save";

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn request(url: &str, curl_args: &[&str]) -> Result<CurlRequest> {
        CurlRequest::new(resolve_hosted_target(url, "block")?, &args(curl_args))
    }

    fn session(cookie_domain: &str, expires_at: &str) -> StoredSessionCredential {
        StoredSessionCredential {
            session_credential: SECRET.to_string(),
            expires_at: Some(expires_at.to_string()),
            cookie_name: Some("bb_hosted_session".to_string()),
            cookie_domain: Some(cookie_domain.to_string()),
        }
    }

    fn valid_session() -> StoredSessionCredential {
        session("apps.block.builderlab.xyz", "2099-01-01T00:00:00Z")
    }

    fn error_code(error: &anyhow::Error) -> (i32, String) {
        let (exit_code, payload) = failure_info(error);

        (
            exit_code,
            payload["error"]["code"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    }

    #[test]
    fn resolves_hosted_apps_of_the_configured_org() {
        let target = resolve_hosted_target(
            "https://MyApp.Apps.Block.Builderlab.xyz/api/items?q=1",
            "block",
        )
        .expect("hosted app");
        assert_eq!(target.host, "myapp.apps.block.builderlab.xyz");
        assert_eq!(target.hosted_domain, "apps.block.builderlab.xyz");
        assert_eq!(
            target.url.as_str(),
            "https://myapp.apps.block.builderlab.xyz/api/items?q=1"
        );

        let staging =
            resolve_hosted_target("https://myapp.apps.block.builderlabstaging.xyz/", "block")
                .expect("staging hosted app");
        assert_eq!(staging.hosted_domain, "apps.block.builderlabstaging.xyz");

        let explicit_port =
            resolve_hosted_target("https://myapp.apps.block.builderlab.xyz:443/", "block")
                .expect("default port");
        assert_eq!(explicit_port.host, "myapp.apps.block.builderlab.xyz");
    }

    #[test]
    fn refuses_hosts_outside_the_tenant_hosted_app_domain() {
        for url in [
            "http://myapp.apps.block.builderlab.xyz/",
            "https://user@myapp.apps.block.builderlab.xyz/",
            "https://user:pass@myapp.apps.block.builderlab.xyz/",
            "https://myapp.apps.block.builderlab.xyz:8443/",
            "https://apps.block.builderlab.xyz/",
            "https://block.builderlab.xyz/",
            "https://app.builderlab.xyz/",
            "https://compose-ctrl.block.builderlab.xyz/",
            "https://myapp.apps.block.builderlab.xyz.evil.example/",
            "https://myapp.apps.block.builderlab.xyz./",
            "https://myapp.apps.block.example.com/",
            "https://myappapps.block.builderlab.xyz/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "ftp://myapp.apps.block.builderlab.xyz/",
            "myapp.apps.block.builderlab.xyz",
            "-v",
        ] {
            let error = resolve_hosted_target(url, "block").expect_err(url);
            assert_eq!(
                error_code(&error),
                (exit_codes::GENERAL, "invalid_hosted_app_url".to_string()),
                "{url}"
            );
        }
    }

    #[test]
    fn refuses_hosted_apps_of_another_tenant() {
        let error = resolve_hosted_target("https://myapp.apps.other.builderlab.xyz/", "block")
            .expect_err("other tenant");
        assert_eq!(error_code(&error).1, "hosted_app_tenant_mismatch");
        assert!(error.to_string().contains("bl config set org other"));
    }

    #[test]
    fn session_cookie_domain_must_cover_the_target_host() {
        let target = resolve_hosted_target(APP_URL, "block").expect("target");
        assert!(usable_session(valid_session(), &target, 0).is_some());
        for cookie_domain in [
            "apps.other.builderlab.xyz",
            "block.builderlab.xyz",
            "builderlab.xyz",
            "other.example",
            "",
        ] {
            assert!(
                usable_session(session(cookie_domain, "2099-01-01T00:00:00Z"), &target, 0)
                    .is_none(),
                "{cookie_domain}"
            );
        }
        let mut no_name = valid_session();
        no_name.cookie_name = None;
        assert!(usable_session(no_name, &target, 0).is_none());
    }

    #[test]
    fn expired_sessions_are_not_used() {
        let target = resolve_hosted_target(APP_URL, "block").expect("target");
        let expires_at = parse_rfc3339_utc("2026-06-15T00:00:00Z").expect("timestamp");
        let stored = session("apps.block.builderlab.xyz", "2026-06-15T00:00:00Z");
        assert!(usable_session(stored.clone(), &target, expires_at - 3600).is_some());
        assert!(usable_session(stored.clone(), &target, expires_at - 30).is_none());
        assert!(usable_session(stored, &target, expires_at + 1).is_none());
        // An unparseable expiry is left to the server to judge.
        let unknown = session("apps.block.builderlab.xyz", "soon");
        assert!(usable_session(unknown, &target, expires_at).is_some());
    }

    #[test]
    fn parses_rfc3339_timestamps() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_utc("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(
            parse_rfc3339_utc("2026-06-15T12:30:45.123456Z"),
            Some(1_781_526_645)
        );
        assert_eq!(
            parse_rfc3339_utc("2026-06-15T14:30:45+02:00"),
            Some(1_781_526_645)
        );
        assert_eq!(
            parse_rfc3339_utc("2026-06-15T07:30:45-05:00"),
            Some(1_781_526_645)
        );
        assert_eq!(parse_rfc3339_utc("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_utc("not a time"), None);
    }

    #[test]
    fn refuses_curl_options_that_could_leak_or_redirect_the_cookie() {
        for curl_args in [
            &["-v"][..],
            &["-sv"],
            &["--verbose"],
            &["--trace", "out.txt"],
            &["--trace-ascii", "-"],
            &["--trace-config", "all"],
            &["--libcurl", "out.c"],
            &["-K", "other.cfg"],
            &["--config", "other.cfg"],
            &["-q"],
            &["--next"],
            &["--url", "https://evil.example"],
            &["-L"],
            &["--location"],
            &["--location-trusted"],
            &["-b", "a=b"],
            &["--cookie", "a=b"],
            &["-c", "jar.txt"],
            &["--cookie-jar", "jar.txt"],
            &["-D", "-"],
            &["--dump-header", "headers.txt"],
            &["-k"],
            &["--insecure"],
            &[
                "--resolve",
                "myapp.apps.block.builderlab.xyz:443:203.0.113.1",
            ],
            &["--connect-to", "::evil.example:443"],
            &["-u", "user:pass"],
            &["--oauth2-bearer", "token"],
            &["-n"],
            &["-H", "Cookie: other=1"],
            &["-H", "cookie;"],
            &["-H", "Authorization: Bearer x"],
            &["-H", "X-BB-Session-Credential: x"],
            &["-H", "@headers.txt"],
            &["https://evil.example/"],
            &["-s", "evil.example"],
            &["-"],
            &["--"],
            &["--proxy", "http://proxy.example"],
            &["--header=Origin: x"],
            &["--made-up"],
            &["-Z"],
            &["-H"],
            &["--no-globoff"],
            &["-s", "--no-globoff", "-g"],
            &["--no-disable"],
            &["--no-get"],
            &["-G", "-d", "a=1", "--no-get"],
            &["--no-head"],
            &["--no-location"],
            &["--no-insecure"],
            &["--no-config"],
            &["--no-request", "GET"],
        ] {
            let error = request(APP_URL, curl_args).expect_err(&format!("{curl_args:?}"));
            assert_eq!(
                error_code(&error),
                (exit_codes::GENERAL, "unsupported_curl_argument".to_string()),
                "{curl_args:?}"
            );
        }
    }

    #[test]
    fn refuses_request_data_from_stdin() {
        for curl_args in [
            &["-d", "@-"][..],
            &["-d@-"],
            &["--data-binary", "@-"],
            &["--json", "@-"],
            &["--data-urlencode", "name@-"],
            &["--data-urlencode", "@-"],
            &["-F", "file=@-"],
            &["-F", "file=<-"],
            &["-T", "-"],
            &["-T", "."],
        ] {
            let error = request(APP_URL, curl_args).expect_err(&format!("{curl_args:?}"));
            assert!(
                error.to_string().contains("read request data from a file"),
                "{curl_args:?}: {error}"
            );
        }
        // Literal data that merely looks similar is fine.
        request(APP_URL, &["--data-raw", "@-", "--form-string", "x=@-"]).expect("literal data");
    }

    #[test]
    fn passes_through_common_curl_options() {
        let request = request(
            APP_URL,
            &[
                "-sS",
                "-fi",
                "-H",
                "Accept: application/json",
                "-HX-Trace: 1",
                "--compressed",
                "--no-compressed",
                "--no-silent",
                "--no-progress-meter",
                "--no-buffer",
                "-o",
                "out.json",
                "-w",
                "%{http_code}\n",
                "--max-time",
                "30",
                "--url-query",
                "page=2",
            ],
        )
        .expect("supported options");
        assert_eq!(request.method, "GET");
        assert_eq!(
            &request.argv()[..5],
            &args(&["-q", "--config", "-", "--globoff", APP_URL])[..]
        );
        assert_eq!(request.argv()[5..], request.user_args[..]);
    }

    #[test]
    fn infers_the_request_method_like_curl() {
        for (curl_args, method) in [
            (&[][..], "GET"),
            (&["-d", "a=1"], "POST"),
            (&["--data-raw", "a=1"], "POST"),
            (&["--json", "{}"], "POST"),
            (&["-F", "a=1"], "POST"),
            (&["-G", "-d", "a=1"], "GET"),
            (&["-I"], "HEAD"),
            (&["-T", "file.txt"], "PUT"),
            (&["-X", "post"], "POST"),
            (&["-XPOST"], "POST"),
            (&["-sSXPOST"], "POST"),
            (&["--request", "DELETE", "-d", "a=1"], "DELETE"),
        ] {
            assert_eq!(
                request(APP_URL, curl_args).expect("request").method,
                method,
                "{curl_args:?}"
            );
        }
    }

    #[test]
    fn adds_origin_only_to_compose_server_action_posts() {
        let origin = Some("https://myapp.apps.block.builderlab.xyz".to_string());
        assert_eq!(
            request(ACTION_URL, &["-d", "{}"]).unwrap().added_origin(),
            origin
        );
        assert_eq!(
            request(ACTION_URL, &["--json", "{}"])
                .unwrap()
                .added_origin(),
            origin
        );
        assert_eq!(
            request(ACTION_URL, &["-X", "POST"]).unwrap().added_origin(),
            origin
        );
        assert_eq!(request(ACTION_URL, &[]).unwrap().added_origin(), None);
        assert_eq!(
            request(ACTION_URL, &["-G", "-d", "a=1"])
                .unwrap()
                .added_origin(),
            None
        );
        assert_eq!(
            request(APP_URL, &["-d", "{}"]).unwrap().added_origin(),
            None
        );
        assert_eq!(
            request(
                "https://myapp.apps.block.builderlab.xyz/_compose/serverless",
                &["-d", "{}"]
            )
            .unwrap()
            .added_origin(),
            None
        );
        for header in [
            "Origin: https://other.example",
            "origin:https://x",
            "ORIGIN;",
        ] {
            assert_eq!(
                request(ACTION_URL, &["-d", "{}", "-H", header])
                    .unwrap()
                    .added_origin(),
                None,
                "{header}"
            );
        }
    }

    #[test]
    fn session_cookie_goes_only_in_the_stdin_config() {
        let request = request(ACTION_URL, &["-s", "-d", "{}"]).expect("request");
        let config = request
            .stdin_config(&valid_session(), Path::new("/tmp/bl \"curl\"\\headers"))
            .expect("config");

        assert!(!request.argv().iter().any(|arg| arg.contains(SECRET)));
        assert!(!request
            .argv()
            .iter()
            .any(|arg| arg.contains("bb_hosted_session")));
        assert_eq!(
            config,
            format!(
                "cookie = \"bb_hosted_session={SECRET}\"\n\
                 header = \"Origin: https://myapp.apps.block.builderlab.xyz\"\n\
                 dump-header = \"/tmp/bl \\\"curl\\\"\\\\headers\"\n"
            )
        );
        assert!(!format!("{request:?}").contains(SECRET));
    }

    #[test]
    fn stdin_config_rejects_values_that_could_inject_curl_options() {
        let request = request(APP_URL, &[]).expect("request");
        for value in ["a\nverbose", "a\"b", "a b", ""] {
            let mut stored = valid_session();
            stored.session_credential = value.to_string();
            assert!(request
                .stdin_config(&stored, Path::new("/tmp/headers"))
                .is_err());
        }
        assert!(request
            .stdin_config(&valid_session(), Path::new("/tmp/a\nverbose"))
            .is_err());
    }

    #[test]
    fn parses_the_final_response_head() {
        let head = parse_response_head(
            "HTTP/1.1 100 Continue\r\n\r\n\
             HTTP/2 401\r\n\
             www-authenticate: Basic realm=x\r\n\
             WWW-Authenticate: BBIdentity\r\n\r\n",
        )
        .expect("head");
        assert_eq!(head.status, 401);
        assert!(head.session_rejected());

        let consent = parse_response_head(
            "HTTP/1.1 401 Unauthorized\r\n\
             WWW-Authenticate: BBIdentity\r\n\
             X-BB-Consent-Url: https://app.builderlab.xyz/consent/abc\r\n\r\n",
        )
        .expect("consent head");
        assert!(consent.consent_required());
        assert!(!consent.session_rejected());

        assert_eq!(parse_response_head("HTTP/1.1 401 Unauthorized\r\n"), None);
        assert_eq!(parse_response_head("HTTP/1.1 100 Continue\r\n\r\n"), None);
        assert!(
            !parse_response_head("HTTP/1.1 401 x\r\nWWW-Authenticate: Bearer\r\n\r\n")
                .unwrap()
                .session_rejected()
        );
    }

    fn header_file(contents: &str) -> TempFile {
        let file = TempFile::create().expect("temp file");
        fs::write(file.path(), contents).expect("write headers");
        file
    }

    #[test]
    fn rejected_session_output_is_withheld_for_retry() {
        let rejected = header_file("HTTP/1.1 401 x\r\nWWW-Authenticate: BBIdentity\r\n\r\n");
        let mut sink = Vec::new();
        let captured =
            forward_output(&b"unauthorized"[..], &mut sink, rejected.path(), true).unwrap();
        assert!(sink.is_empty());
        assert_eq!(captured, b"unauthorized");

        // Without holding, everything is forwarded as it arrives.
        let mut sink = Vec::new();
        forward_output(&b"unauthorized"[..], &mut sink, rejected.path(), false).unwrap();
        assert_eq!(sink, b"unauthorized");

        let ok = header_file("HTTP/1.1 200 OK\r\n\r\n");
        let mut sink = Vec::new();
        forward_output(&b"body"[..], &mut sink, ok.path(), true).unwrap();
        assert_eq!(sink, b"body");

        let consent = header_file(
            "HTTP/1.1 401 x\r\nWWW-Authenticate: BBIdentity\r\nX-BB-Consent-Url: https://x\r\n\r\n",
        );
        let mut sink = Vec::new();
        forward_output(
            &b"{\"error\":\"consent_required\"}"[..],
            &mut sink,
            consent.path(),
            true,
        )
        .unwrap();
        assert_eq!(sink, b"{\"error\":\"consent_required\"}");
    }

    #[test]
    fn consent_body_is_shown_even_without_the_consent_header() {
        let rejected = header_file("HTTP/1.1 401 x\r\nWWW-Authenticate: BBIdentity\r\n\r\n");
        let body = br#"{"error":"consent_required","approval_url":"https://app.builderlab.xyz/approve/1"}"#;
        let mut sink = Vec::new();
        let captured = forward_output(&body[..], &mut sink, rejected.path(), true).unwrap();
        assert_eq!(sink, body);
        assert_eq!(captured, body);
    }

    #[test]
    fn finds_consent_errors_in_the_response_body() {
        let approval = "https://app.builderlab.xyz/approve/1";
        let body = format!(r#"{{"error":"consent_required","approval_url":"{approval}"}}"#);
        assert_eq!(
            consent_url_from_body(body.as_bytes()).as_deref(),
            Some(approval)
        );
        assert_eq!(
            consent_url_from_body(format!(" \n{body}\n").as_bytes()).as_deref(),
            Some(approval)
        );
        // With -i, the headers come first.
        let included =
            format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: BBIdentity\r\n\r\n{body}");
        assert_eq!(
            consent_url_from_body(included.as_bytes()).as_deref(),
            Some(approval)
        );
        for other in [
            r#"{"error":"unauthorized","approval_url":"https://x"}"#,
            r#"{"error":"consent_required"}"#,
            r#"{"error":"consent_required","approval_url":7}"#,
            "unauthorized",
            "",
        ] {
            assert_eq!(consent_url_from_body(other.as_bytes()), None, "{other}");
        }
    }
    struct FakeSessions {
        stored: RefCell<Option<StoredSessionCredential>>,
        logins: Cell<usize>,
        forgets: Cell<usize>,
    }

    impl FakeSessions {
        fn new(stored: Option<StoredSessionCredential>) -> Self {
            Self {
                stored: RefCell::new(stored),
                logins: Cell::new(0),
                forgets: Cell::new(0),
            }
        }
    }

    impl HostedSessions for FakeSessions {
        fn stored(&self) -> Result<Option<StoredSessionCredential>> {
            Ok(self.stored.borrow().clone())
        }

        fn login(&self) -> Result<StoredSessionCredential> {
            self.logins.set(self.logins.get() + 1);
            let mut fresh = valid_session();
            fresh.session_credential = format!("fresh-{}", self.logins.get());
            *self.stored.borrow_mut() = Some(fresh.clone());
            Ok(fresh)
        }

        fn forget(&self) -> Result<()> {
            self.forgets.set(self.forgets.get() + 1);
            *self.stored.borrow_mut() = None;
            Ok(())
        }
    }

    struct RecordedRun {
        argv: Vec<String>,
        config: String,
        hold_rejected_output: bool,
    }

    struct FakeCurl {
        responses: RefCell<VecDeque<(Option<ResponseHead>, Vec<u8>)>>,
        runs: RefCell<Vec<RecordedRun>>,
    }

    impl FakeCurl {
        fn new(responses: impl IntoIterator<Item = Option<ResponseHead>>) -> Self {
            Self::with_output(responses.into_iter().map(|response| (response, Vec::new())))
        }

        fn with_output(
            responses: impl IntoIterator<Item = (Option<ResponseHead>, Vec<u8>)>,
        ) -> Self {
            Self {
                responses: RefCell::new(responses.into_iter().collect()),
                runs: RefCell::new(Vec::new()),
            }
        }
    }

    impl CurlRunner for FakeCurl {
        fn run(
            &self,
            argv: &[String],
            stdin_config: &dyn Fn(&Path) -> Result<String>,
            hold_rejected_output: bool,
        ) -> Result<CurlOutcome> {
            self.runs.borrow_mut().push(RecordedRun {
                argv: argv.to_vec(),
                config: stdin_config(Path::new("/tmp/headers"))?,
                hold_rejected_output,
            });
            let (response, output_prefix) = self
                .responses
                .borrow_mut()
                .pop_front()
                .expect("unexpected curl run");
            Ok(CurlOutcome {
                exit_code: 0,
                response,
                output_prefix,
            })
        }
    }

    fn status(status: u16) -> Option<ResponseHead> {
        Some(ResponseHead {
            status,
            ..ResponseHead::default()
        })
    }

    fn bbidentity_401() -> Option<ResponseHead> {
        Some(ResponseHead {
            status: 401,
            www_authenticate: vec!["BBIdentity".to_string()],
            consent_url: None,
        })
    }

    fn consent_401(url: &str) -> Option<ResponseHead> {
        Some(ResponseHead {
            status: 401,
            www_authenticate: vec!["BBIdentity".to_string()],
            consent_url: Some(url.to_string()),
        })
    }

    #[test]
    fn logs_in_when_no_session_is_stored() {
        let sessions = FakeSessions::new(None);
        let curl = FakeCurl::new([status(200)]);
        let request = request(APP_URL, &["-s"]).unwrap();

        assert_eq!(run_request(&sessions, &curl, &request).unwrap(), 0);
        assert_eq!(sessions.logins.get(), 1);
        let runs = curl.runs.borrow();
        assert_eq!(runs.len(), 1);
        assert!(!runs[0].hold_rejected_output);
        assert!(runs[0]
            .config
            .contains("cookie = \"bb_hosted_session=fresh-1\""));
        assert!(!runs[0].argv.iter().any(|arg| arg.contains("fresh-1")));
    }

    #[test]
    fn uses_a_valid_stored_session_without_logging_in() {
        let sessions = FakeSessions::new(Some(valid_session()));
        let curl = FakeCurl::new([status(200)]);
        let request = request(APP_URL, &[]).unwrap();

        assert_eq!(run_request(&sessions, &curl, &request).unwrap(), 0);
        assert_eq!(sessions.logins.get(), 0);
        let runs = curl.runs.borrow();
        assert!(runs[0].hold_rejected_output);
        assert!(runs[0].config.contains(SECRET));
        assert!(!runs[0].argv.iter().any(|arg| arg.contains(SECRET)));
    }

    #[test]
    fn logs_in_instead_of_using_an_expired_or_foreign_session() {
        for stored in [
            session("apps.block.builderlab.xyz", "2000-01-01T00:00:00Z"),
            session("apps.other.builderlab.xyz", "2099-01-01T00:00:00Z"),
        ] {
            let sessions = FakeSessions::new(Some(stored));
            let curl = FakeCurl::new([status(200)]);
            run_request(&sessions, &curl, &request(APP_URL, &[]).unwrap()).unwrap();
            assert_eq!(sessions.logins.get(), 1);
            assert!(!curl.runs.borrow()[0].config.contains(SECRET));
        }
    }

    #[test]
    fn drops_a_rejected_stored_session_and_logs_in_once() {
        let sessions = FakeSessions::new(Some(valid_session()));
        let curl = FakeCurl::new([bbidentity_401(), status(200)]);
        let request = request(APP_URL, &["-s"]).unwrap();

        assert_eq!(run_request(&sessions, &curl, &request).unwrap(), 0);
        assert_eq!(sessions.forgets.get(), 1);
        assert_eq!(sessions.logins.get(), 1);
        let runs = curl.runs.borrow();
        assert_eq!(runs.len(), 2);
        assert!(runs[0].hold_rejected_output);
        assert!(runs[0].config.contains(SECRET));
        assert!(!runs[1].hold_rejected_output);
        assert!(runs[1].config.contains("bb_hosted_session=fresh-1"));
    }

    #[test]
    fn resends_only_safe_methods_after_logging_in_again() {
        for (curl_args, resent) in [
            (&[][..], true),
            (&["-G", "-d", "q=1"], true),
            (&["-I"], true),
            (&["-X", "OPTIONS"], true),
            (&["-X", "get"], true),
            (&["-d", "{}"], false),
            (&["--data-raw", "{}"], false),
            (&["--json", "{}"], false),
            (&["-F", "a=1"], false),
            (&["-T", "file.txt"], false),
            (&["-X", "DELETE"], false),
            (&["-XPATCH"], false),
            (&["-I", "-X", "POST"], false),
        ] {
            let sessions = FakeSessions::new(Some(valid_session()));
            let curl = FakeCurl::new(
                [bbidentity_401()]
                    .into_iter()
                    .chain(resent.then(|| status(200))),
            );
            let result = run_request(&sessions, &curl, &request(APP_URL, curl_args).unwrap());

            // The session is refreshed either way.
            assert_eq!(sessions.forgets.get(), 1, "{curl_args:?}");
            assert_eq!(sessions.logins.get(), 1, "{curl_args:?}");
            let runs = curl.runs.borrow();
            assert_eq!(runs.len(), if resent { 2 } else { 1 }, "{curl_args:?}");
            // Output is held back only when the request will be resent.
            assert_eq!(runs[0].hold_rejected_output, resent, "{curl_args:?}");
            if resent {
                assert_eq!(result.unwrap(), 0, "{curl_args:?}");
            } else {
                let error = result.expect_err("not resent");
                assert_eq!(
                    error_code(&error),
                    (
                        exit_codes::AUTH_REQUIRED,
                        "hosted_session_refreshed".to_string()
                    ),
                    "{curl_args:?}"
                );
                assert!(error.to_string().contains("Rerun the command"));
            }
        }
    }

    #[test]
    fn consent_error_body_without_the_header_is_consent_required() {
        let approval = "https://app.builderlab.xyz/apps/myapp/consent?request=abc";
        let body = format!(r#"{{"error":"consent_required","approval_url":"{approval}"}}"#);
        let sessions = FakeSessions::new(Some(valid_session()));
        let curl = FakeCurl::with_output([(bbidentity_401(), body.into_bytes())]);
        let error = run_request(&sessions, &curl, &request(APP_URL, &[]).unwrap())
            .expect_err("consent required");

        assert_eq!(
            error_code(&error),
            (exit_codes::AUTH_REQUIRED, "consent_required".to_string())
        );
        assert!(error.to_string().contains(approval));
        assert_eq!(sessions.logins.get(), 0);
        assert_eq!(sessions.forgets.get(), 0);
        assert_eq!(curl.runs.borrow().len(), 1);
    }
    #[test]
    fn does_not_loop_when_a_fresh_session_is_rejected() {
        let sessions = FakeSessions::new(Some(valid_session()));
        let curl = FakeCurl::new([bbidentity_401(), bbidentity_401()]);
        let error = run_request(&sessions, &curl, &request(APP_URL, &[]).unwrap())
            .expect_err("fresh session rejected");
        assert_eq!(
            error_code(&error),
            (
                exit_codes::AUTH_REQUIRED,
                "hosted_session_rejected".to_string()
            )
        );
        assert_eq!(sessions.logins.get(), 1);
        assert_eq!(curl.runs.borrow().len(), 2);

        let sessions = FakeSessions::new(None);
        let curl = FakeCurl::new([bbidentity_401()]);
        run_request(&sessions, &curl, &request(APP_URL, &[]).unwrap())
            .expect_err("fresh session rejected");
        assert_eq!(sessions.logins.get(), 1);
        assert_eq!(curl.runs.borrow().len(), 1);
    }

    #[test]
    fn consent_required_prints_the_approval_url_without_relogin() {
        let approval = "https://app.builderlab.xyz/apps/myapp/consent?request=abc";
        let sessions = FakeSessions::new(Some(valid_session()));
        let curl = FakeCurl::new([consent_401(approval)]);
        let error = run_request(&sessions, &curl, &request(APP_URL, &[]).unwrap())
            .expect_err("consent required");

        assert_eq!(
            error_code(&error),
            (exit_codes::AUTH_REQUIRED, "consent_required".to_string())
        );
        assert!(error.to_string().contains(approval));
        let (_, payload) = failure_info(&error);

        assert_eq!(payload["error"]["details"]["approval_url"], approval);
        assert_eq!(sessions.logins.get(), 0);
        assert_eq!(sessions.forgets.get(), 0);
        assert_eq!(curl.runs.borrow().len(), 1);
    }

    #[test]
    fn consent_required_without_a_usable_url_still_fails() {
        let sessions = FakeSessions::new(Some(valid_session()));
        let curl = FakeCurl::new([consent_401("javascript:alert(1)")]);
        let error = run_request(&sessions, &curl, &request(APP_URL, &[]).unwrap())
            .expect_err("consent required");
        assert_eq!(error_code(&error).1, "consent_required");
        assert!(!error.to_string().contains("javascript"));
    }

    #[test]
    fn other_responses_return_the_curl_exit_code() {
        for response in [status(403), status(500), None] {
            let sessions = FakeSessions::new(Some(valid_session()));
            let curl = FakeCurl::new([response]);
            assert_eq!(
                run_request(&sessions, &curl, &request(APP_URL, &[]).unwrap()).unwrap(),
                0
            );
            assert_eq!(sessions.logins.get(), 0);
        }
    }

    fn curl_available() -> bool {
        ProcessCommand::new("curl")
            .arg("--version")
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    /// Serve one request; return the request head and body.
    fn serve_once(response: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse().unwrap();
                    }
                }
                head.push_str(&line);
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
            head + &String::from_utf8_lossy(&body)
        });
        (url, handle)
    }

    #[test]
    fn system_curl_sends_the_cookie_from_stdin_and_reads_the_response() {
        if !curl_available() {
            eprintln!("skipping: curl is not installed");
            return;
        }
        let (base_url, server) = serve_once(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: BBIdentity\r\nContent-Length: 12\r\nConnection: close\r\n\r\nunauthorized",
        );
        let request = request(ACTION_URL, &["-s", "-d", "{}"]).unwrap();
        // Same argv shape as a real run, pointed at the loopback server.
        let mut argv = request.argv();
        argv[4] = format!("{base_url}/_compose/server/save");

        let outcome = SystemCurl
            .run(
                &argv,
                &|header_file| request.stdin_config(&valid_session(), header_file),
                true,
            )
            .expect("run curl");
        let received = server.join().expect("server");

        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.response.expect("response").session_rejected());
        assert!(
            received.contains(&format!("Cookie: bb_hosted_session={SECRET}\r\n")),
            "{received}"
        );
        assert!(received.contains("Origin: https://myapp.apps.block.builderlab.xyz\r\n"));
        assert!(received.starts_with("POST /_compose/server/save "));
        assert!(received.ends_with("{}"));
        assert!(!argv.iter().any(|arg| arg.contains(SECRET)));
    }

    /// One request as seen by [`TestApp`].
    #[derive(Clone, Debug)]
    struct SeenRequest {
        method: String,
        path: String,
        cookie: Option<String>,
        body: String,
    }

    /// A local HTTP server that answers every request with `respond`.
    struct TestApp {
        base_url: String,
        seen: std::sync::Arc<std::sync::Mutex<Vec<SeenRequest>>>,
    }

    impl TestApp {
        fn start(respond: impl Fn(&SeenRequest) -> String + Send + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let log = seen.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or_default().to_string();
                    let path = parts.next().unwrap_or_default().to_string();
                    let (mut cookie, mut content_length) = (None, 0);
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" || line.is_empty() {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':') {
                            if name.eq_ignore_ascii_case("content-length") {
                                content_length = value.trim().parse().unwrap();
                            }
                            if name.eq_ignore_ascii_case("cookie") {
                                cookie = Some(value.trim().to_string());
                            }
                        }
                    }
                    let mut body = vec![0; content_length];
                    reader.read_exact(&mut body).unwrap();
                    let request = SeenRequest {
                        method,
                        path,
                        cookie,
                        body: String::from_utf8_lossy(&body).into_owned(),
                    };
                    let response = respond(&request);
                    log.lock().unwrap().push(request);
                    let _ = stream.write_all(response.as_bytes());
                }
            });
            Self { base_url, seen }
        }

        fn seen(&self) -> Vec<SeenRequest> {
            self.seen.lock().unwrap().clone()
        }
    }

    fn http_response(status: &str, headers: &[&str], body: &str) -> String {
        let mut response = format!("HTTP/1.1 {status}\r\n");
        for header in headers {
            response.push_str(header);
            response.push_str("\r\n");
        }
        response.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ));
        response
    }

    /// The system curl, with each hosted-app URL pointed at a local server.
    struct LocalCurl {
        base_url: String,
    }

    impl CurlRunner for LocalCurl {
        fn run(
            &self,
            argv: &[String],
            stdin_config: &dyn Fn(&Path) -> Result<String>,
            hold_rejected_output: bool,
        ) -> Result<CurlOutcome> {
            let mut argv = argv.to_vec();
            let url = Url::parse(&argv[4]).expect("hosted-app URL");
            argv[4] = format!("{}{}", self.base_url, url.path());
            SystemCurl.run(&argv, stdin_config, hold_rejected_output)
        }
    }

    #[test]
    fn rejected_post_is_not_resent_and_its_effect_happens_once() {
        if !curl_available() {
            eprintln!("skipping: curl is not installed");
            return;
        }
        let saves = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = saves.clone();
        // The app acts on the request and then answers 401 BBIdentity.
        let app = TestApp::start(move |request| {
            if request.method == "POST" && request.path == "/_compose/server/save" {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            http_response(
                "401 Unauthorized",
                &["WWW-Authenticate: BBIdentity"],
                "unauthorized",
            )
        });
        let output = TempFile::create().expect("output file");
        let output_path = output.path().to_str().unwrap().to_string();
        let request = request(ACTION_URL, &["-s", "-o", &output_path, "-d", "{\"n\":1}"]).unwrap();
        let sessions = FakeSessions::new(Some(valid_session()));

        let error = run_request(
            &sessions,
            &LocalCurl {
                base_url: app.base_url.clone(),
            },
            &request,
        )
        .expect_err("POST is not resent");

        assert_eq!(error_code(&error).1, "hosted_session_refreshed");
        assert_eq!(saves.load(std::sync::atomic::Ordering::SeqCst), 1);
        let seen = app.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].body, "{\"n\":1}");
        assert_eq!(
            seen[0].cookie.as_deref(),
            Some(format!("bb_hosted_session={SECRET}").as_str())
        );
        // The session was still refreshed for the rerun.
        assert_eq!(sessions.forgets.get(), 1);
        assert_eq!(sessions.logins.get(), 1);
    }

    #[test]
    fn revoked_hosted_session_is_rejected_by_a_later_request() {
        if !curl_available() {
            eprintln!("skipping: curl is not installed");
            return;
        }
        let revoked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let revocations = revoked.clone();
        let app = TestApp::start(move |request| {
            let cookie = request.cookie.clone().unwrap_or_default();
            if request.method == "POST" && request.path == "/v1/auth/logout" {
                revocations.lock().unwrap().push(cookie);
                return http_response("200 OK", &[], "{}");
            }
            if cookie.is_empty() || revocations.lock().unwrap().contains(&cookie) {
                return http_response(
                    "401 Unauthorized",
                    &["WWW-Authenticate: BBIdentity"],
                    "unauthorized",
                );
            }
            http_response("200 OK", &[], "ok")
        });
        let client =
            builderlab_auth::auth_login::build_auth_http_client(std::time::Duration::from_secs(5))
                .expect("client");

        // `bl auth logout` revokes the stored session with its hosted cookie.
        assert!(
            builderlab_auth::auth_login::logout_hosted_session_credential(
                &client,
                None,
                &app.base_url,
                &valid_session(),
            )
            .expect("revoke hosted session")
        );

        // A later `bl curl` with that session is rejected; it logs in again.
        let output = TempFile::create().expect("output file");
        let output_path = output.path().to_str().unwrap().to_string();
        let sessions = FakeSessions::new(Some(valid_session()));
        let exit_code = run_request(
            &sessions,
            &LocalCurl {
                base_url: app.base_url.clone(),
            },
            &request(APP_URL, &["-s", "-o", &output_path]).unwrap(),
        )
        .expect("resent with a new session");

        assert_eq!(exit_code, 0);
        assert_eq!(fs::read_to_string(output.path()).unwrap(), "ok");
        let seen = app.seen();
        let cookies = seen
            .iter()
            .map(|request| {
                (
                    request.path.as_str(),
                    request.cookie.clone().unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        let old_cookie = format!("bb_hosted_session={SECRET}");
        assert_eq!(
            cookies,
            [
                ("/v1/auth/logout", old_cookie.clone()),
                ("/api/items", old_cookie),
                ("/api/items", "bb_hosted_session=fresh-1".to_string()),
            ]
        );
        assert_eq!(sessions.forgets.get(), 1);
        assert_eq!(sessions.logins.get(), 1);
    }

    #[test]
    fn consent_body_written_to_an_output_file_is_consent_required() {
        if !curl_available() {
            eprintln!("skipping: curl is not installed");
            return;
        }
        let approval = "https://app.builderlab.xyz/apps/myapp/consent?request=abc";
        let body = format!(r#"{{"error":"consent_required","approval_url":"{approval}"}}"#);
        // No X-BB-Consent-Url and no Content-Type, as after a lossy ingress.
        let app = TestApp::start(move |_| {
            http_response("401 Unauthorized", &["WWW-Authenticate: BBIdentity"], &body)
        });
        let output = TempFile::create().expect("output file");
        let output_path = output.path().to_str().unwrap().to_string();
        let sessions = FakeSessions::new(Some(valid_session()));

        let error = run_request(
            &sessions,
            &LocalCurl {
                base_url: app.base_url.clone(),
            },
            &request(APP_URL, &["-s", "-o", &output_path]).unwrap(),
        )
        .expect_err("consent required");

        assert_eq!(
            error_code(&error),
            (exit_codes::AUTH_REQUIRED, "consent_required".to_string())
        );
        assert!(error.to_string().contains(approval));
        assert_eq!(sessions.logins.get(), 0);
        assert_eq!(sessions.forgets.get(), 0);
        assert_eq!(app.seen().len(), 1);
    }

    #[test]
    fn output_file_honours_output_dir() {
        let request = request(APP_URL, &["--output-dir", "out", "-o", "body.json"]).unwrap();
        assert_eq!(
            request.output_file,
            Some(Path::new("out").join("body.json"))
        );
        let request = request_with_stdout();
        assert_eq!(request.output_file, None);
    }

    fn request_with_stdout() -> CurlRequest {
        request(APP_URL, &["-o", "-"]).unwrap()
    }
}
