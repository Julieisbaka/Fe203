# Fe203 Changelog

## `0.0.5`

- Added `--pretty` for formatted JSON/SARIF output.
- Added FE065 (`test-without-product-reference`) to flag test code that never references product code.

## `0.0.4`

- Added opt-in CLI syntax checking via `--check-syntax`.
- Added `--max` mode that runs `cargo check` + `cargo test` automatically and enables all built-in rules.
- Added SARIF output via `--sarif` (SARIF v2.1.0 JSON).
- Added GitHub release automation that builds and publishes versioned Windows/Linux/macOS binary archives with SHA256 checksums.
- Added Windows first-run auto PATH registration for downloaded release binaries (disable with `FE203_NO_AUTO_PATH=1`).
- Changed no-argument invocation (`fe203`) to show an intro/quick-start screen instead of immediately scanning `.`.
- Improved `--help`/intro rendering for terminal compatibility (narrow terminal wrapping and ASCII fallback with `FE203_ASCII=1` / `TERM=dumb`).
- Added baseline workflows:
  - `--init-baseline [FILE]` to capture the current finding set
  - `--baseline <FILE>` to suppress previously known findings
- Added per-rule severity overrides via `[severity]` in `fe203.toml`.
- Added manifest-aware Cargo target expansion:
  - scans from directories or `Cargo.toml` targets now expand `[workspace].members`
- Added fix examples alongside rule suggestions in human and JSON output.
- Improved Cargo package/bin build metadata to support cleaner CLI installation via `cargo install --path .`.

## `0.0.3`

- Added two new rule families: `shell` (FE100, FE101) for shell command
  construction risks, and `path` (FE120, FE121) for path traversal /
  untrusted path-join risks.
- Added file-level suppression via `// fe203-ignore-file <tokens>`, in
  addition to the existing line-level `fe203-ignore`.
- Fixed a false positive in FE061 (empty doc comment) where a blank
  `///`/`//!` line used as an intentional paragraph break inside a larger
  doc comment was incorrectly flagged.
- Fixed a false positive in FE083 (unanchored validation regex) where
  ordinary `.find(` calls unrelated to regex (e.g. iterator/string `.find(`)
  were incorrectly flagged; the rule now also requires the literal to
  contain a regex metacharacter.
- Fixed a path-matching bug where a single `*` in an exclude/include glob
  pattern could incorrectly cross a `/` directory boundary.
- Tightened `[paths]` exclude/include matching so slash-containing patterns
  are resolved relative to the scan root first, with a full-path fallback
  for backward compatibility.
- Added more regex-heuristic fixtures and unit tests.
- Applied `fe203-ignore-file` suppression comments across the
  rule-implementation and test source files so a self-scan of the Fe203
  repository is quieter.

## `0.0.2`

- Added `--explain <ID>` for per-rule explanations.
- Added `--init-config [FILE]` for generating a `fe203.toml` template.
- Added generated rule index output via `--list-rules`.
- Added line-level comment suppression with `fe203-ignore`.
- Added multi-line clamp detection.
- Added more regex heuristics:
  - dynamic regex construction
  - unanchored validation regexes
- Added unused-variable and unused-constant lint rules.
- Added config support for `[paths].include`.
- Added `.gitignore` seeding for generated config templates.

## `0.0.1`

- Initial crate scaffold.
- Debug macro rules.
- Unsafe usage rules.
- Hardcoded secret detection.
- Basic clamp, regex, and empty-comment linting.
