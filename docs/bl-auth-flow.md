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
  prints the approval URL and exits with code 3.
- `401` with `WWW-Authenticate: BBIdentity` for a stored session: `bl curl`
  forgets the session, logs in again once, and retries. The rejected
  response's output is withheld so the retry does not duplicate it.
- Server actions (`POST /_compose/server/*`) need a same-origin `Origin`
  header. `bl curl` sends `Origin: https://<app host>` unless the caller set
  one.

`bl auth logout` deletes the stored hosted-app sessions for the configured org.
