# Architecture

Fe203 is intentionally modular, std-only, and text-first. It does not build a
Rust AST and does not perform whole-program dataflow analysis. That keeps the
tool small and fast, but it also means it is best at simple, high-signal
heuristics rather than deep semantic analysis.

## Module Layout

- `src/cli.rs` — parses arguments with the standard library.
- `src/config.rs` — parses a small TOML subset without external crates.
- `src/finding.rs` — shared `Finding`, `Severity`, and `Category` types.
- `src/rules/mod.rs` — the `Rule` trait, the `all_rules()` registry, rule
  index/explain rendering, and suppression helpers.
- `src/scanner.rs` — file discovery, `[paths]` glob matching, and the scan
  pipeline that runs enabled rules over discovered files.
- `src/reporting.rs` — human-readable and JSON rendering of findings.

## Per-Category Rule Modules

- `src/rules/debug_code.rs` — `debug` category rules.
- `src/rules/unsafe_usage.rs` — `unsafe` category rules.
- `src/rules/secrets.rs` — `secrets` category rules.
- `src/rules/lint.rs` — `lint` category rules.
- `src/rules/regex_checks.rs` — `regex` category rules.

See [rules/overview.md](rules/overview.md) for how new rule modules (such as
the `shell` and `path` families) plug into this same structure.

## Known Limitations

- Regex heuristics are heuristic, not semantic regex analysis.
- Text-based scanning can flag intentional matches in literals, tests, or docs.
- Unused-variable detection is intentionally shallow and may miss more complex
  destructuring or block-scoped cases.
- Suppression is line/file-based, not AST-aware (see [suppressions.md](suppressions.md)).
- `Cargo.toml` scanning is opt-in through `[paths].include`.
