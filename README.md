# BuilderLab CLI

`bl` is the command-line interface for BuilderLab. It provides authenticated
access to BuilderLab skills, agents, workspaces, apps, and Blox workstations,
along with the `bl tools` command for discovering configured tool extensions.

The CLI is written in Rust and is built from this repository. Run `bl --help`
to see the current command surface:

```text
auth         Manage BuilderLab marketplace authentication
workspace    Manage BuilderLab workspaces
apps         Manage apps through Apps Platform
compute      Manage Blox workstations
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

For inherited Apps Platform trace context and failure correlation, see
[Apps operation correlation](docs/apps-operation-correlation.md).

On a BuilderLab Blox workstation, the operator sets `BL_APPS_CONTROL_PLANE_URL`.
For that origin, the CLI delegates authentication to Roxy and needs no local
login or organization configuration. Roxy obtains a short-lived Compose JWT
from KGoose for the workstation owner and injects it on the wire. Any other
URL, including an explicit `--base-url` outside that origin, must be an
approved HTTPS ingress and requires `bl auth login`.

## Blox workstations

Use your existing `bl auth login` session to create and inspect Blox workstations:

```bash
bl compute skus
bl compute create my-workstation --multiple 2
bl compute list
bl compute get <name-or-full-id>
bl compute list --include-deleted --limit 20 --offset 20 --json
bl compute exec my-workstation -- uname -a
bl compute suspend my-workstation
bl compute resume my-workstation
bl compute delete my-workstation
```

`bl blox` remains available as a hidden compatibility alias for `bl compute`.

The Blox endpoint defaults to the deployment associated with your BuilderLab
login: Block staging, public staging, or public production. Block production
does not currently deploy Blox. Override the endpoint with
`bl compute --base-url <url> list` or `BL_BLOX_CONTROL_PLANE_URL`. The CLI accepts
only the approved HTTPS ingress origins `blox.test.blockstaging.build`,
`blox.public.builderlabstaging.xyz`, and `blox.public.builderlab.xyz`.

The CLI verifies the same stored session used by the other BuilderLab commands
and sends it as `Authorization: BBIdentity` to Blox ingress. No additional
login or token configuration is required. Redirects are disabled.

`list` returns your workstations, omits connection details, and defaults to 100
results. Use `--limit 0` for all results; a nonzero `--offset` requires a
nonzero limit. `get` forwards your selector to the orchestrator, which resolves
an active canonical name before a numeric ID. Display labels are not selectors;
use the full ID for archived workstations. JSON output retains the generated
protobuf response shape, including string-encoded 64-bit counts. Help and shell
completions work offline.

`create [NAME]` always requests a new workstation. Its default SKU is
`DEFAULT_AMD64`, the SKU available in public BuilderLab staging; `--multiple`
defaults to 1 and must be positive. Use `bl compute skus` to see the codes and
maximum multiples available to your account, and override with `--sku CODE`
when needed. The deployment validates SKU availability and multiples. The CLI
accepts no CPU, memory, repository, or prompt options. It requests no project
repositories; the deployment may still bootstrap your configured home repository.

Creation returns the initial workstation ID and status without waiting for
readiness. Inspect it with `bl compute get <id>`. If the response is lost or cannot
be read, the CLI reports an unknown result and does not retry automatically.
Inspect `bl compute list` or `bl compute get <name>` before trying again to avoid
creating a second workstation. Preserve any `--base-url` override for these checks.

`suspend`, `resume`, and `delete` accept a canonical workstation name or full ID.
The CLI resolves the target once and sends one transition request. It reports
the server's response without waiting for the final state; use `bl compute get <id>`
to inspect progress. Suspension can take several minutes while capturing a
snapshot, then resource teardown may continue after the response. A resume
response does not establish readiness, and deletion may continue asynchronously.

Deletion archives the workstation. Resume after deletion depends on whether the
deployment retained a usable snapshot; use its full ID because archived names
are not resolved. If a transition result is uncertain, inspect that exact ID
using the same Blox endpoint before trying again. Lifecycle requests are never
retried automatically.

`exec <WORKSTATION> -- <COMMAND> [ARG...]` runs an executable with literal
arguments, streams its stdout and stderr, and exits with the remote process's
exit status. Use `--workdir PATH` before `--` to choose a remote directory;
otherwise Blox selects the workstation's configured directory. Shell expansion
and pipelines require an explicit shell, for example:

```bash
bl compute exec my-workstation -- sh -c 'printf hello; uname -a'
```

Execution is noninteractive: stdin and PTY allocation are unsupported. Commands
can run longer than 30 seconds. Interrupting the CLI or losing its connection
may leave the durable command running. The CLI never retries execution; if a
result is uncertain, inspect the command in Blox before starting another copy.

With `--json`, execution prints JSONL events with `workstation_id`, `command_id`,
and `output` containing the generated protobuf stream response (its `data` bytes
are base64). A final event contains the process's `exit_code`. Local or service
failures retain the normal JSON error envelope on stderr; a remote nonzero exit
does not add an error envelope.

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
| `BL_BLOX_CONTROL_PLANE_URL` | Override the approved Blox control-plane ingress. |
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
- `crates/blox/` contains generated orchestrator protocol types and its Connect client.
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
