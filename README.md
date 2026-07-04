# Fe203

Fe203 is a fast yet powerful CLI tool for scanning and linting Rust code. Fe203 is not just a linting tool. It checks for security issues, code quality, best practices, errors, and more. It is designed to be fast, accurate, and easy to use.

## Why the name Fe203?

The primary component of rust is $$Fe_2O_3$$.
The full chemical formula of rust also has $$H_2O$$ (Water), but the amount is variable.

## Installation

Build from source (no external dependencies — pure std):

```sh
cargo build --release
# binary at target/release/fe203
```

Install into your Cargo bin directory:

```sh
cargo install --path .
# then run: fe203 --version
```

Upgrade an existing Cargo-installed copy:

```sh
cargo install --path . --force
```

Install from GitHub release binaries:

1. Open the project Releases page.
2. Download the archive for your platform/target.
3. Extract and run `fe203` (or `fe203.exe`) once.

On Windows, Fe203 updates user `PATH` registration automatically and prioritizes
the newest detected `fe203.exe` install so older copies are less likely to
shadow newer upgrades. Open a new terminal after first run or after
reinstalling.

Set `FE203_NO_AUTO_PATH=1` to disable this behavior.

Release assets are published with stable names:

- `fe203-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`
- `fe203-vX.Y.Z-x86_64-apple-darwin.tar.gz`
- `fe203-vX.Y.Z-x86_64-pc-windows-msvc.zip`

These names are intended to make winget/Scoop manifest maintenance straightforward.

## Usage

```sh
fe203 [OPTIONS] [PATH]...
fe203                # show intro + quick-start commands
fe203 .              # scan the current directory
fe203 --json src/    # emit JSON for a specific path
fe203 -j --pretty src/  # short flags are supported for common options
fe203 --rules=FE001,FE080 --categories=debug,secrets src/
fe203 --json --pretty src/  # emit pretty-printed JSON
fe203 --check-syntax # runs cargo check; unsafe on untrusted repos
fe203 --max          # runs cargo check + cargo test + all rules; unsafe on untrusted repos
fe203 --list-rules   # print the built-in rule index
fe203 --check-update # check GitHub Releases for a newer version
fe203 --self-update  # update from latest release binary (Windows x86_64)
```

`--check-syntax` and `--max` invoke Cargo on the target project. Do not use
them on untrusted repositories unless you are willing to run that repository's
build scripts, proc macros, tests, and related Cargo-driven code.

`--self-update` selects the matching release asset for the current OS and
architecture when one is published. It replaces the existing installed binary
in place and launches the updated CLI automatically.

## Documentation

- [docs/README.md](docs/README.md) — full documentation index (CLI reference,
  configuration, suppressions, architecture, rules, and roadmap).
- [docs/changelog.md](docs/changelog.md) — release history.
- [docs/contributing.md](docs/contributing.md) — contribution guidance.

## Benchmarking

Use built-in benchmark mode to measure end-to-end CLI scan time against
the workload folder in `benchmarks/workload`.

Run with defaults (5 measured iterations):

```sh
fe203 --benchmark
```

Run against a custom path and iteration count:

```sh
fe203 --benchmark 10 benchmarks/workload
```

The harness prints per-run timing and a summary (`min`, `max`, `mean`,
`median`).
