# Building `bl`

`bl-cli` owns the Rust `bl` binary. It no longer owns standalone app,
installer, archive, DMG, MSI, package, or platform-specific distribution.
Berd.app bundles the `bl` binary and manages the `/usr/local/bin/bl` command
link from the app.

The Homebrew-backed `sq` command-pack release path is separate and documented in
`docs/RELEASING-sq.md`.

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

## Berd Integration

Berd packages `bl` by copying a built binary into the app resources during the
Berd bundle flow. In the parent app repo, this is handled by:

```text
scripts/prepare-bl-cli-resource.sh
```

The packaged app exposes the command from:

```text
Berd.app/Contents/Resources/bl
```

Berd.app owns installing or repairing:

```text
/usr/local/bin/bl -> /Applications/Berd.app/Contents/Resources/bl
```

## Ownership

Do not add standalone `bl` app, installer, platform archive, DMG, MSI, package,
or Homebrew distribution back to this package. Distribution flows through
Berd.app.

When changing `bl`, update and merge the version in `Cargo.toml`, run the normal
`bl-cli` checks, and validate the Berd bundle path that consumes the binary.
