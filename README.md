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

## Usage

```sh
fe203 [OPTIONS] [PATH]...
fe203                # scan the current directory
fe203 --json src/    # emit JSON for a specific path
fe203 --check-syntax # opt-in cargo syntax/type check before scanning
fe203 --max          # run cargo check + cargo test + all rules before scanning
fe203 --list-rules   # print the built-in rule index
```

## Documentation

- [docs/README.md](docs/README.md) — full documentation index (CLI reference,
  configuration, suppressions, architecture, rules, and roadmap).
- [docs/changelog.md](docs/changelog.md) — release history.
- [docs/contributing.md](docs/contributing.md) — contribution guidance.
