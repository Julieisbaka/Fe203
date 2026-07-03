# Architecture

Fe203 is intentionally modular, std-only, and text-first. It does not build a
full Rust AST and does not perform whole-program dataflow analysis. That keeps
the tool small and fast, but it also means it is best at simple, high-signal
heuristics rather than deep semantic analysis. For a few rules where raw text
matching is too noisy, Fe203 now uses lightweight hand-rolled syntax-aware
parsing for specific constructs such as annotated test functions.

## Module Layout

- `src/cli/` — parses arguments and renders help text with the standard library.
- `src/config.rs` — parses a small TOML subset without external crates.
- `src/finding.rs` — shared `Finding`, `Severity`, and `Category` types.
- `src/rules/mod.rs` — the `Rule` trait, the `all_rules()` registry, rule
  index/explain rendering, and suppression helpers.
- `src/scanner/` — file discovery, `[paths]` glob matching, caching, and the scan
  pipeline that runs enabled rules over discovered files.
- `src/reporting.rs` — human-readable and JSON rendering of findings.

## Per-Category Rule Modules

- `src/rules/debug_code.rs` — `debug` category rules.
- `src/rules/unsafe_usage.rs` — `unsafe` category rules.
- `src/rules/secrets.rs` — `secrets` category rules.
- `src/rules/lint/` — `lint` category rules.
- `src/rules/regex_checks/` — `regex` category rules.

See [rules/overview.md](rules/overview.md) for how new rule modules (such as
the `shell` and `path` families) plug into this same structure.

## Known Limitations

- Regex heuristics are heuristic, not semantic regex analysis.
- Text-based scanning can flag intentional matches in literals, tests, or docs.
- Some rules use lightweight syntax-aware parsing, but Fe203 still does not do
  full type resolution, macro expansion, or borrow-aware name analysis.
- Unused-variable detection now follows multi-line bindings and common
  block-scoped shadow chains, but it is still heuristic and may miss more
  complex macro-generated or control-flow-sensitive cases.
- Suppression is line/file-based, not AST-aware (see [suppressions.md](suppressions.md)).
- `Cargo.toml` scanning is opt-in through `[paths].include`.
