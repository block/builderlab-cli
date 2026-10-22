# BuilderLab CLI

`bl` is the command-line interface for BuilderLab. It provides authenticated
access to BuilderLab skills, agents, workspaces, and apps, along with the
`bl tools` command for discovering configured tool extensions.

The CLI is written in Rust and is built from this repository. Run `bl --help`
to see the current command surface:

```text
auth         Manage BuilderLab marketplace authentication
workspace    Manage BuilderLab workspaces
apps         Manage apps through Apps Platform
config       Get and set bl preferences
skills       Manage BuilderLab skills
agents       Manage BuilderLab marketplace agents
completions  Generate shell completions
tools        Discover auth-backed tool extensions
```

## Quick start

This repository uses the Hermit-managed toolchain. From the repository root:

```bash
source ./bin/activate-hermit
just build-bl-release
target/release/bl --help
```

For a debug build during development:

```bash
cargo build --locked --bin bl
./target/debug/bl --version
```

Service access requires an existing BuilderLab account and a reachable backend.
The inherited default is Block's internal `https://kgoose.sqprod.co`; building
this public repository does not grant access to that service. For another
BuilderLab installation, set `KGOOSE_BASE_URL` to the base URL supplied by its
operator before logging in. Organization configuration does not replace that
base URL.

Authenticate before using commands that access BuilderLab services:

```bash
./target/debug/bl auth login
./target/debug/bl auth status
./target/debug/bl skills list
```

The CLI can also configure the organization used for service routing:

```bash
./target/debug/bl config set org <org>
./target/debug/bl config get org
```

`bl tools` (or `bl tools --help`) fetches the configured extensions from the
selected KGoose backend. Extensions whose credentials are missing for the caller
appear with `[not connected]` beside their description. The same live list is
used by `bl tools --describe-commands`. Listing requires backend access and
authentication, just like inspecting or calling an extension's tools.
When inspecting an extension fails, `bl tools` also uses the live extension list
to distinguish an unknown name from a configured extension that is not connected.

The separately packaged `sq agent-tools` command uses the embedded
`extensions.yaml` catalog for its top-level help and command discovery.

Use `--json` for machine-readable output and `--verbose` for request
diagnostics. Do not include credentials or other sensitive data when sharing
verbose output.

## Managed MySQL apps

When the selected Apps Platform contract and server support managed MySQL,
create a fetch-js app with:

```bash
bl apps create --app-id inventory --runtime-profile fetch-js --persistence mysql --json
```

The command plans, reserves the exact app ID, and initializes its database
before returning success. MySQL supports `fetch-js` and `process` apps; pass
the runtime explicitly. MySQL is unavailable for `static` apps.
The client preserves server availability errors; it does not fall back to SQLite.

For an existing app, inspect it first. To resume failed initialization or
enable MySQL on a compatible stateless server app, use its existing runtime:

```bash
bl apps get inventory --json
bl apps initialize inventory --runtime-profile fetch-js --persistence mysql --json
```

`initialize` checks that the app exists, plans the requested settings, and
initializes the same ID without another reservation. It does not reclaim
deleted apps or migrate an existing database to another engine. Use the same
selected endpoint and environment throughout. Check the returned
`initialize.persistence` is `mysql` before deploying the matching runtime artifact.
Deleting a MySQL app revokes its database access, but the database data is retained.

For inherited Apps Platform trace context and failure correlation, see
[Apps operation correlation](docs/apps-operation-correlation.md).

On a BuilderLab Blox workstation, the operator sets `BL_APPS_CONTROL_PLANE_URL`.
For that origin, the CLI delegates authentication to Roxy and needs no local
login or organization configuration. Roxy obtains a short-lived Compose JWT
from KGoose for the workstation owner and injects it on the wire. Any other
URL, including an explicit `--base-url` outside that origin, must be an
approved HTTPS ingress and requires `bl auth login`.

## Apps validation errors

Apps HTTP failures include `error.details.http_status` in JSON output and retain
the server error code and available trace ID. For HTTP 400
`artifact_manifest_invalid`, human output and `error.details.validation` give
repair guidance. Missing `hotpod.manifest.json` and missing fetch-js `ASSETS` or
`HOTPOD` bindings get specific diagnostics; other manifest failures point to
the selected control plane's advertised schemas and runtime requirements.
Rebuild the artifact after fixing it, then explicitly deploy again.
Use the same control plane for contract discovery, carrying forward any
`--base-url` override used for the rejected request.

The CLI generates validation details from fixed public validator messages.
Unknown backend messages and raw bodies remain hidden; malformed or unavailable
responses retain the generic HTTP failure. Existing server recovery strings are
credential-redacted and terminal-safe. This does not retry failed mutations.

## Apps quota and recovery

`bl apps list --scope owned --json` preserves the server's optional `quota`
metadata. `quota.current_count` is authoritative owner usage, including held
deploy reservations. The list's `count` describes visible apps and can differ.
Check `accounting_enabled`, `enforcement_enabled` and `tier_status` before using
the current allowance. Missing quota metadata does not mean zero or unlimited
usage; an unavailable tier has no reliable tier-derived limit.

Apps JSON errors retain the public object fields from `error.details`, alongside
the CLI's `http_status` and reviewed validation diagnostics. Top-level
`next_action` preserves string or structured recovery guidance. Credentials and
terminal controls are sanitized only in these error recovery fields. Unsafe
object keys omit the affected field. Successful JSON data, including multiline
debug logs and deletion metadata, retains its original shape and contents after
credential redaction. Authentication failures keep local auth guidance and do
not expose server details.

For `owner_site_limit_reached`, inspect owned apps on the same control plane,
delete only an app you no longer need, then refresh authoritative usage before
retrying. Existing counted apps remain manageable at the cap. Initialization
does not consume quota; a validated deployment claims a slot, and failure after
admission can retain that reservation until retry or owner deletion.

Deletion requires the exact app and environment confirmations. A retired route
does not prove capacity was released: `quota_cleanup_pending: true` means the
slot remains held. Inspect the same app/environment and refresh
`bl apps list --scope owned --include-deleted --json`; explicitly retry cleanup
until the server confirms release. Owner reconciliation and unavailable quota
or tier services require recovery before another mutation. The CLI does not
automatically delete apps or retry failed mutations.

## Local development

Install the repository tools and git hooks once:

```bash
./bin/hermit install rustup just lefthook
source ./bin/activate-hermit
just setup
```

Run the standard checks:

```bash
just fmt-check
just lint
just test
just ci
```

Run the isolated Docker acceptance harness for the skills workflows:

```bash
just bl-cli-docker-acceptance
```

For browser-based authentication and local service testing, see:

- [BuilderLab Auth Flow](docs/bl-auth-flow.md)
- [BuilderLab Local Auth Testing](docs/bl-auth-local-testing.md)

## Configuration

The most useful configuration options are:

| Variable | Purpose |
| --- | --- |
| `BL_HOME` | Override the BuilderLab state directory. |
| `BL_SKILLS_HOME` | Override the installed skills directory. |
| `BL_SKILLS_CONFIG` | Select an explicit skills configuration file. |
| `BL_SKILLS_PROFILE` | Select a skills configuration profile. |
| `BL_AUTH_STORAGE` | Select authentication storage, including `file` for local testing. |
| `BL_AUTH_STORAGE_FILE` | Path used when file-backed auth storage is selected. |
| `KGOOSE_BASE_URL` | Override the backend base URL for local development. |
| `BL_KGOOSE_PLAYPEN` | Route backend requests through a named development playpen. |

For example, a local backend can be used without changing the stored profile:

```bash
KGOOSE_BASE_URL=http://localhost:8080 \
  ./target/debug/bl --local-dev skills list
```

Authentication storage defaults to the operating-system keyring where
supported. The local auth guide documents file-backed storage for tests and
development without modifying keyring state.

## Project layout

- `src/bl/` contains the `bl` command implementations.
- `crates/builderlab-auth/` contains browser login, session storage, workspace,
  and organization-routing support.
- `src/lib.rs` wires the CLI runtime and test harness together.
- `tests/bl_e2e.rs` contains the offline and mock-service end-to-end coverage.
- `docker/acceptance/` contains the isolated skills acceptance harness.
- `docs/RELEASING-bl.md` describes release builds and downstream packaging.

## Release and distribution

Build a release binary with:

```bash
source ./bin/activate-hermit
just build-bl-release
target/release/bl --version
```

This repository owns the `bl` binary, which can be used independently of Berd
or Buzz. Standalone downloads and app-assisted installation or updates are
planned; for now, build from source. See [RELEASING-bl.md](docs/RELEASING-bl.md)
for the current build and distribution status.

## Contributing

- [Contributing guide](CONTRIBUTING.md)
- [Report a bug or request a feature](https://github.com/block/builderlab-cli/issues/new/choose)
- [Security policy](SECURITY.md)
- [Block Open Source governance](GOVERNANCE.md)
- [Apache License 2.0](LICENSE)

## Moving from `bb`

The executable and environment variables now use `bl` and `BL_`. The default
state directory is `~/.bl`; existing `~/.bb` preferences and agent installation
records are not automatically moved. To continue using that state, explicitly
set `BL_HOME="$HOME/.bb"` before running `bl`, and translate any `BB_` overrides
to their `BL_` equivalents. Keep the same backend URL and profile to reuse a
stored session. macOS keychain IDs and skill/agent ownership metadata retain
their legacy names so existing credentials and managed installs remain usable.
Do not use `--force` just to adopt an existing installation.

The backend `X-BB-Session-Credential` header, `BBIdentity` authorization scheme,
`builderbot` extension ID, and
Playpen routing key are protocol identifiers and retain their existing names.
On Linux and Windows, keyring login storage is not implemented; the explicit
`BL_AUTH_STORAGE=file` option is available as described in the local auth guide.

On managed bb-public Blox workstations, `bl workspace list` uses the same
operator-configured Kgoose endpoint and Roxy owner identity as `bl tools`.
It needs no local org setting or `bl auth login`, and does not read or write
local session credentials. The server derives the org from the verified owner
and returns that owner's current workspace memberships. This requires the
shared workspace-list endpoint to accept workstation authentication, with the
matching Roxy policy deployed.
`bl workspace switch` continues to require a local CLI login; listing does not
change the workstation's active workspace or rotate a session.
