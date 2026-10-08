# Building and distributing `bl`

This repository owns the BuilderLab CLI. It can be built and used independently
of Berd or Buzz. The intended distribution options include standalone downloads
and installation or updates assisted by those applications. The release and
update mechanisms are still being worked out.

The Homebrew-backed `sq` command-pack release path is separate and documented in
[RELEASING-sq.md](RELEASING-sq.md).

## Local Build

Build the release binary:

```bash
source ./bin/activate-hermit
cargo build --locked --release --bin bl
```

Or use the Justfile alias:

```bash
source ./bin/activate-hermit
just build-bl-release
```

Smoke-check the built CLI:

```bash
target/release/bl --version
target/release/bl --help
```

## Distribution status

Apps Platform sends an independently maintained compatibility version in
`X-Hotpod-Agent-Client-Version` (currently `0.2.0`). This is separate from the
standalone package version shown by `bl --version` and the User-Agent. Review
Apps protocol compatibility when changing that value; resetting the package
version for a beta release must not lower the Apps compatibility version.
`--client-version` / `BL_APPS_CLIENT_VERSION` explicitly override it.

For now, build `bl` from source using the commands above. This repository does
not yet provide a standalone installer or published binary release workflow.

Future distribution should support users who want BuilderLab capabilities
without installing Berd or Buzz. App-assisted installation and updates are
also planned; packaging, signing, installation paths, and update behavior
are not specified here yet.
