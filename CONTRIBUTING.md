# Contributing to BuilderLab CLI

BuilderLab CLI is developed by Block in the open. You can inspect the source,
build it locally, and help us improve it by filing a clear issue or proposing a
focused change.

## Filing an issue

Open an issue through the [issue chooser](https://github.com/block/builderlab-cli/issues/new/choose).
Use the bug report template for behavior that does not match the documented
CLI, and the feature request template for a capability or improvement.

Blank issues are disabled so that reports contain enough information to act on.
Issues created through the API or other tooling should meet the same standard.

### Using an agent

An agent can help gather version information, reduce logs, and turn notes into
clear reproduction steps. You are still responsible for the issue: read the
result before posting it, and never let an agent invent versions, output, or
other details it did not observe. Write `unknown` when you do not know
something.

### Before filing

Please:

1. Search open and closed issues and link the closest match, or say that you
   found none.
2. Reproduce the problem with the current release or current `main` build.
3. Keep one problem per issue so it can be triaged and closed cleanly.

### Bug reports

A useful bug report lets a maintainer reproduce the problem without a long
back-and-forth. Include:

- the exact command and relevant inputs;
- expected and actual behavior;
- whether it happens every time or intermittently;
- the CLI name and exact version;
- operating system and installation or build method; and
- the relevant output or log excerpt.

Put output in a fenced code block, include only the relevant lines, and remove
credentials, tokens, prompts, file paths, and other sensitive information.

### Feature requests

Describe the problem you are trying to solve before proposing a solution.
Include:

- what you do today and any workaround;
- why the capability belongs in BuilderLab CLI;
- what is explicitly out of scope; and
- alternatives you considered and why they were insufficient.

## What happens next

Issues are triaged on a best-effort basis. A report may be labelled and queued,
returned for more information, closed as a duplicate, or closed as out of
scope with an explanation. A closed issue is not a judgment on the person who
filed it; it records a product decision.

## Security issues

Do not open a public issue for a security vulnerability. Follow the private
reporting instructions in [SECURITY.md](SECURITY.md).

## Building locally

BuilderLab CLI uses the Hermit-managed toolchain. From the repository root:

```bash
source ./bin/activate-hermit
just build
just test
just lint
```

Run the complete local verification suite before submitting a change:

```bash
just ci
```

If the repository tools have not been installed yet:

```bash
./bin/hermit install rustup just lefthook
source ./bin/activate-hermit
just setup
```

See the [README](README.md) for package and CLI usage, and [AGENTS.md](AGENTS.md)
for repository layout and implementation notes.

## Pull requests

Keep changes focused and explain the user-visible behavior they change. Add or
update tests and documentation when appropriate. Before requesting review:

- run `just ci`;
- confirm that generated or packaged artifacts are intentional; and
- remove local paths, credentials, and unrelated changes from the diff.

The [Block Open Source governance guide](GOVERNANCE.md) also applies to
participation in this repository.
