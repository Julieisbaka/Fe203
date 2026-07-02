# Fe203 Documentation

This is the documentation index for Fe203, a std-only CLI for scanning and linting Rust source code.

## Guides

- [getting-started.md](getting-started.md) — install, quick start, first scan, first config, first `--explain`.
- [cli-reference.md](cli-reference.md) — full flag and command reference, plus the finding output shape.
- [configuration.md](configuration.md) — the `fe203.toml` format, precedence rules, and path-matching semantics.
- [suppressions.md](suppressions.md) — line-level and file-level `fe203-ignore` comment suppression.
- [architecture.md](architecture.md) — implementation model, module layout, and known limitations.
- [roadmap.md](roadmap.md) — suggested next features.

## Rules

- [rules/overview.md](rules/overview.md) — the `Rule` trait model, rule IDs, severities, and how to add a rule.
- [rules/debug.md](rules/debug.md) — `debug` category: `todo!()`, `unimplemented!()`, `dbg!()`, `panic!()`.
- [rules/unsafe.md](rules/unsafe.md) — `unsafe` category: `unsafe` blocks and `unsafe fn` declarations.
- [rules/secrets.md](rules/secrets.md) — `secrets` category: hardcoded password/API key/secret assignments.
- [rules/lint.md](rules/lint.md) — `lint` category: clamp chains, empty comments, unused variables/constants.
- [rules/regex.md](rules/regex.md) — `regex` category: nested quantifiers, dynamic construction, unanchored validation.
- [rules/shell.md](rules/shell.md) — `shell` category: command execution and shell string injection.
- [rules/path.md](rules/path.md) — `path` category: path traversal and unsanitized path joins.

## Project

- [changelog.md](changelog.md) — release history.
- [contributing.md](contributing.md) — contribution guidance.

See the [root README](../README.md) for a short project overview.
