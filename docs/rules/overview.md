# Rules Overview

Fe203 rules implement a shared `Rule` trait. Each rule declares a stable ID, a
name, a category, a severity, and scan logic that produces zero or more
findings for a file.

## Registry

All built-in rules are registered in `all_rules()` in `src/rules/mod.rs`. This
registry backs `--list-rules`, `--explain`, and category/rule filtering.

## Rule IDs

Rule IDs use the short `FE###` scheme (e.g. `FE080`). IDs are stable and are
never reused, even if a rule is removed.

## Severities

- `info`
- `warning`
- `high`
- `critical`

## Categories

- [debug.md](debug.md) — `debug`
- [unsafe.md](unsafe.md) — `unsafe`
- [secrets.md](secrets.md) — `secrets`
- [lint.md](lint.md) — `lint`
- [regex.md](regex.md) — `regex`
- [shell.md](shell.md) — `shell`
- [path.md](path.md) — `path`

## Adding a New Rule

1. Implement the `Rule` trait in a module under `src/rules/` (create a new
   module for a new category, or add to an existing one).
2. Register the rule in `all_rules()` in `src/rules/mod.rs`.
3. Optionally add a new category if the rule doesn't fit an existing one.
4. Add a unit test, and update the relevant doc file under `docs/rules/`.

See [../contributing.md](../contributing.md) for the full contribution workflow.
