# Fe203

Fe203 is a fast yet powerful CLI tool for scanning and linting rust code.

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
```

Scan the current directory:

```sh
fe203
```

Scan specific paths, emit JSON, or run only some checks:

```sh
fe203 src/ crates/
fe203 --json src/
fe203 --categories secrets src/
fe203 --categories lint,regex src/
fe203 --rules FE001,FE004 src/
fe203 --list-rules
```

Exit codes: `0` = clean, `1` = findings reported, `2` = usage/config error.

## Rules (v0.0.1)

| ID | Category | Severity | Detects |
|----|----------|----------|---------|
| FE001 | debug | warning | `todo!()` |
| FE002 | debug | warning | `unimplemented!()` |
| FE003 | debug | warning | `dbg!()` |
| FE004 | debug | warning | `panic!()` |
| FE020 | unsafe | info | `unsafe` blocks/impls |
| FE021 | unsafe | warning | `unsafe fn` declarations |
| FE040 | secrets | high | `password = "..."` assignments |
| FE041 | secrets | high | `api_key = "..."` assignments |
| FE042 | secrets | high | `secret = "..."` assignments |
| FE060 | lint | info | clamp-like `.max(...).min(...)` / `.min(...).max(...)` chains |
| FE061 | lint | warning | empty doc comments like `///` or `//!` |
| FE062 | lint | info | empty comments like `//` or `/* */` |
| FE063 | lint | warning | unused local variables |
| FE064 | lint | warning | unused constants |
| FE080 | regex | warning | nested quantifiers like `(a+)+` |
| FE081 | regex | info | suspicious regex wildcards / empty alternation |

## Configuration

Fe203 reads `fe203.toml` from the working directory (or pass `--config <file>`).
Everything is enabled by default; the config only needs to list what you change:

```toml
[rulesets]
# Enable or disable whole categories.
debug = true
unsafe = true
secrets = true
lint = true
regex = true

[rules]
# Per-rule overrides win over category toggles.
FE003 = false   # allow dbg!()

[paths]
# Directory or file names skipped during discovery.
exclude = ["target", ".git"]
include = ["Cargo.toml"]
```

Precedence: per-rule toggle → category toggle → default (enabled).
CLI filters (`--rules`, `--categories`) are applied on top of the config.

`build.rs` files are already scanned automatically because they are Rust source.
`Cargo.toml` is optional: add it to `[paths].include` when you want the scanner
to walk project manifest files too, which becomes useful as you add
manifest-aware rules.

## Fix suggestions

Every finding now includes a small remediation hint in both the human-readable
output and the JSON output. For example, a manual clamp-like chain suggests
using `.clamp(lower, upper)`, and hardcoded-secret findings suggest moving the
value into environment-based configuration.

## Adding a new rule

The engine is modular by design:

1. Implement the `Rule` trait in a module under `src/rules/`
   (see `src/rules/debug_code.rs` for the simplest example).
2. Register it in `all_rules()` in `src/rules/mod.rs`.
3. It is now automatically listable (`--list-rules`), configurable by ID,
   and toggleable via its category — no other wiring needed.

## Development

```sh
cargo test    # unit + integration tests
cargo run -- src/
```
