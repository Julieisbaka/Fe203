# Getting Started

## Install

Build from source (no external dependencies — pure std):

```sh
cargo build --release
# binary at target/release/fe203
```

## Your First Scan

Scan the current directory:

```sh
fe203
```

Scan specific paths:

```sh
fe203 src/ crates/
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

## Next Steps

- Full flag reference: [cli-reference.md](cli-reference.md)
- Suppressing a specific finding: [suppressions.md](suppressions.md)
- Browse rule categories: [rules/overview.md](rules/overview.md)
