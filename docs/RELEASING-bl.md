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

For now, build `bl` from source using the commands above. This repository does
not yet provide a standalone installer or published binary release workflow.

Future distribution should support users who want BuilderLab capabilities
without installing Berd or Buzz. App-assisted installation and updates are
also planned; packaging, signing, installation paths, and update behavior
are not specified here yet.
