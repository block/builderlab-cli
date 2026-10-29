# BuilderLab Auth Flow

This is the intended browser-mediated CLI login flow. Web and CLI can use the same backend Auth0 login path, but the resulting credentials are typed and presented differently.

```mermaid
sequenceDiagram
    participant CLI
    participant Browser as User Browser
    participant Backend
    participant Auth0
    participant Store as Backend Data Store

    CLI->>CLI: Generate random state and PKCE verifier; start localhost callback server
    CLI->>Browser: Open /v1/auth/login?type=cli&returnTo=http://127.0.0.1:<port>/callback&state=...&code_challenge=...&code_challenge_method=S256
    Browser->>Backend: Begin CLI login
    Backend->>Store: Store AuthTransaction with type=cli and loopback returnTo
    Backend-->>Browser: Set oauth state cookie, 302 to Auth0 authorize
    Browser->>Auth0: Complete Auth0 login
    Auth0-->>Browser: 302 to configured /v1/auth/callback with code and state
    Browser->>Backend: GET /v1/auth/callback with oauth state cookie
    Backend->>Auth0: Exchange code using stored PKCE verifier
    Auth0-->>Backend: ID/access token response
    Backend->>Store: Create short-lived one-time code for CLI login
    Backend-->>Browser: 302 to localhost callback with code and client state
    Browser->>CLI: GET /callback?code=...&state=...
    CLI->>CLI: Require exactly one matching state before accepting code or error
    CLI->>Backend: POST /v1/auth/login/exchange { code, code_verifier }
    Backend->>Store: Verify code is valid, unused, unexpired, type=cli, and matches PKCE challenge
    Backend->>Store: Create cli session credential
    Backend-->>CLI: Return cli session credential
    CLI->>Backend: API request with X-BB-Session-Credential: <cli session>
```

Security constraints:

- Web sessions are returned as secure cookies and accepted only as cookies.
- CLI sessions are returned by the exchange endpoint and accepted only via the `X-BB-Session-Credential` header. This is a backend wire-protocol name and is not changed by the BuilderLab product rename.
- Durable session credentials are never placed in redirect URLs.
- The localhost redirect carries only a short-lived, single-use exchange code.
- CLI `returnTo` targets must be loopback URLs.
- Each login generates independent 256-bit random state and PKCE verifier values. The CLI sends only the S256 challenge in the login URL and keeps the verifier in memory until exchange.
- Callbacks with missing, mismatched, or duplicate state are rejected without consuming the pending login.
- Waiting for the browser callback times out after ten minutes; rerun `bl auth login` to start a fresh attempt.

## Hosted-app sessions for `bl curl`

Hosted apps accept only the tenant's hosted-site session cookie. CLI sessions
are rejected there by design. `bl curl` instead requests a `cli_hosted`
session: the same tenant-wide hosted-app session a browser gets (same
privileges and lifetime as a web hosted session), delivered to the CLI. Each
request is still authorized per app by the existing registration, ACL, and
workspace checks.

The login is the CLI flow above with `type=cli_hosted`:

1. `bl curl <url>` checks that the URL is `https`, has no user info or
   non-default port, and that its host is `<app>.apps.<tenant>.<root>` where
   `<tenant>` is the configured org and `<root>` is a BuilderLab domain. Other
   hosts are refused before any login or request.
2. Without an unexpired stored session for that hosted-app domain, it opens
   `/v1/auth/login?type=cli_hosted&returnTo=<loopback callback>&state=...&code_challenge=...&code_challenge_method=S256`,
   with fresh state and PKCE values and the same callback checks as `type=cli`.
3. `POST /v1/auth/login/exchange {code, code_verifier}` returns the hosted
   credential with `cookie_name`, `cookie_domain`, and `expires_at`. The CLI
   stores it only if `cookie_domain` is exactly the tenant's hosted-app domain
   (for example `apps.block.builderlab.xyz`).
4. The session is stored in the same auth storage as the CLI session (OS
   keyring on macOS, file elsewhere) under a separate key scoped to the
   profile, server, and hosted-app domain.
5. `bl curl` runs the system `curl` and passes the session as the single
   hosted-site cookie (`Cookie: <cookie_name>=<credential>`) through
   `curl --config -` on stdin. It is never on the command line or in output.
   No `Authorization` or `X-BB-Session-Credential` header is sent.

Responses:

- `401` with `X-BB-Consent-Url`: the app needs the user's approval. `bl curl`
  prints the approval URL and exits with code 3. A `401` whose body is
  `{"error":"consent_required","approval_url":"<url>"}` is treated the same
  way even without the header or a JSON `Content-Type`, since ingress may
  drop them. The body is read from stdout output or the `-o` file.
- `401` with `WWW-Authenticate: BBIdentity` for a stored session: `bl curl`
  forgets the session and logs in again once. The app itself can return this
  after acting on a request, so only `GET`, `HEAD`, and `OPTIONS` requests
  are resent, with the rejected response's output withheld so the retry does
  not duplicate it. For any other method `bl curl` does not resend the
  request: it shows the response and exits with code 3, asking the user to
  rerun the command with the new session. The method is derived as curl
  would: from `-X`, `-I`, `-G`, `-T`, and the `-d`/`--data*`/`--json`/`-F`
  body options.
- Server actions (`POST /_compose/server/*`) need a same-origin `Origin`
  header. `bl curl` sends `Origin: https://<app host>` unless the caller set
  one.

`bl curl` keeps `-q` (no `.curlrc`) and `--globoff` (one URL is one request)
in force: `-K`, `--disable`, `--no-disable`, and `--no-globoff` are refused,
and so are `--no-get` and `--no-head`, which would change the method `bl curl`
derived. Other `--no-<flag>` forms are accepted only for flags that do not
affect the request.

`bl auth logout` revokes each stored hosted-app session for the configured org
by sending it to `POST /v1/auth/logout` as the hosted-site cookie
(`Cookie: <cookie_name>=<credential>`), then deletes the local copy whatever
the result. Revocation is best effort, as for the CLI session. The JSON
output reports each session under `hosted_sessions` (`hosted_domain`,
`server_revoked`, `removed`) and the totals in
`hosted_sessions_server_revoked` and `hosted_sessions_removed`, alongside
`server_revoked` for the CLI session.
