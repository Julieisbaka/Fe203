# Getting Started

## Install

Build from source (no external dependencies — pure std):

```sh
cargo build --release
# binary at target/release/fe203
```

Install locally:

```sh
cargo install --path .
```

Upgrade an existing local install:

```sh
cargo install --path . --force
```

Install from release binaries:

1. Download the matching archive from GitHub Releases.
2. Extract `fe203`/`fe203.exe`.
3. Run it once.

On Windows, Fe203 attempts to add its own folder to your user `PATH` on first
run. Open a new terminal afterward.

Set `FE203_NO_AUTO_PATH=1` to disable automatic PATH registration.

## Your First Scan

Scan the current directory:

```sh
fe203 .
```

Running `fe203` with no path prints a quick-start intro screen.

Human-readable findings always include `path:line:column`. On narrow or
redirected terminals, Fe203 automatically switches to a stacked layout so long
messages stay readable without horizontal wrapping.

Scan specific paths:

```sh
fe203 src/ crates/
```

Run an opt-in syntax/type check before scanning:

```sh
fe203 --check-syntax
```

`--check-syntax` runs `cargo check` on the target project. Treat it as unsafe
for untrusted repositories because Cargo can execute build scripts, proc macros,
and other project-controlled code during the check.

Run maximum validation mode (checks + tests + all rules):

```sh
fe203 --max
```

`--max` is also unsafe for untrusted repositories. It runs both `cargo check`
and `cargo test`, so it can execute test code in addition to build-time Cargo
hooks.

Benchmark repeated scans against a folder:

```sh
fe203 --benchmark
fe203 --benchmark 10 benchmarks/workload
```

## Your First Config

Generate a starter `fe203.toml`:

```sh
fe203 --init-config
```

This seeds sensible exclusions from `.gitignore` when one is present. See
[configuration.md](configuration.md) for the full format.

## Your First `--explain`

List the built-in rules, then look at one in detail:

```sh
fe203 --list-rules
fe203 --explain FE080
```

## Baseline and SARIF

Generate a baseline from current findings, then scan while suppressing already-known items:

```sh
fe203 --init-baseline
fe203 --baseline fe203.baseline
```

Emit SARIF for CI/code scanning:

```sh
fe203 --sarif > fe203.sarif
```

## Next Steps

- Full flag reference: [cli-reference.md](cli-reference.md)
- Suppressing a specific finding: [suppressions.md](suppressions.md)
- Browse rule categories: [rules/overview.md](rules/overview.md)
