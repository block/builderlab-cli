# BuilderLab CLI

`bl` is the command-line interface for BuilderLab. It provides authenticated
access to BuilderLab skills, agents, workspaces, and apps, along with the
`bl tools` command for discovering connected tool extensions.

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

Use `--json` for machine-readable output and `--verbose` for request
diagnostics. Do not include credentials or other sensitive data when sharing
verbose output.

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
