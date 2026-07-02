# Fe203

Fe203 is a fast yet powerful CLI tool for scanning and linting Rust code.

## Why the name Fe203?

The primary component of rust is $$Fe_2O_3$$.
The full chemcial formula of rust also has $$H_2O$$ (Water), but the amount is variable.

## Installation

Build from source (no external dependencies — pure std):

```sh
cargo build --release
# binary at target/release/fe203
```

## Usage

```sh
fe203 [OPTIONS] [PATH]...
fe203                # scan the current directory
fe203 --json src/    # emit JSON for a specific path
fe203 --list-rules   # print the built-in rule index
```

## Documentation

- [docs/README.md](docs/README.md) — full documentation index (CLI reference,
  configuration, suppressions, architecture, rules, and roadmap).
- [docs/changelog.md](docs/changelog.md) — release history.
- [docs/contributing.md](docs/contributing.md) — contribution guidance.
