# Fe203 Changelog

## `0.1.3`

- Optimized scan fingerprint construction to write directly into a preallocated `String` with `push_str`, reducing temporary allocations in the cache-key path.
- Integrated benchmark mode into the main CLI via `fe203 --benchmark [N] <TARGET>`.

## `0.1.2`

- Optimized scan caching to keep one cache session for the full run instead of reloading/saving per chunk.
- Reused a single rule-ID lookup map across chunk scans to reduce repeated setup overhead.
- Removed cache-hit cloning of cached finding vectors by reading cached entries by reference.
- Reduced repeated environment checks in scan orchestration (`FE203_NO_CACHE` now evaluated once per run).
- Added built-in CLI benchmark mode via `fe203 --benchmark [N] <TARGET>` and removed the separate benchmark binary.

## `0.1.1`

- Refactored scanner internals into focused modules (`scanner/discovery`, `scanner/scan`, `scanner/cache`, `scanner/patterns`) while preserving public scanner APIs.
- Added bounded parallel file scanning using available CPU parallelism with deterministic output ordering.
- Switched runtime scanning to streamed chunk processing (discover and scan incrementally) to reduce peak memory usage on large repositories.
- Optimized FE066 (`dead-suppression-comment`) by evaluating stale suppressions from already-collected per-file active rule IDs, avoiding an extra full in-rule rescan pass.
- Updated progress reporting to include scanned/discovered file counts and scan throughput (files/second).

## `0.1.0`

- Expanded the `secrets` rule family with FE043 (`hardcoded-token`) and FE044 (`hardcoded-credential-url`).
- Added FE066 (`dead-suppression-comment`) to flag stale suppression rule IDs.
- Added FE075 (`assert-only-tests-without-product-calls`) for test functions that assert without calling product code.
- Added scan progress status lines in human output mode (disable with `FE203_NO_PROGRESS=1`).
- Optimized scanning with a per-file scan index and cheap rule prefilter signatures.
- Updated `--max` to bypass rule prefiltering so all enabled rules always run.
- Added incremental scan caching (`.fe203/scan-cache.v1`) keyed by file hash and scan fingerprint (disable with `FE203_NO_CACHE=1`).
- Precompiled include/exclude path patterns during discovery for faster directory walking.
- Added shared byte-level comment/string-skipping identifier scanner utility and reused it in lint unused detection.
- Expanded CLI argument parsing:
  - added short aliases for common flags (`-j`, `-s`, `-p`, `-l`, `-r`, `-g`, `-x`, `-b`, `-B`)
  - added `--flag=value` support for value-taking options
  - allowed repeated `--rules` and `--categories` arguments with merged values

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
