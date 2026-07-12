# Fe203 Changelog

## `0.2.2`

- Fixed `--self-update` on Unix: staging now uses a unique temporary filename so a stale leftover from a previous failed update (potentially owned by a different user) no longer blocks the next attempt.
- Fixed `--self-update` on Windows: the replacement script now retries renaming the old binary with backoff before copying the new one, handling brief post-exit file locks from antivirus scanners or the OS.

## `0.2.1`

- Fixed Windows PATH auto-registration to prioritize the newest detected `fe203.exe` version across PATH entries so older installs do not keep shadowing newer upgrades.
- Added `--check-update` to query GitHub Releases and report when a newer Fe203 version is available.
- Added OS-aware `--self-update` to download the matching GitHub Release binary, replace the existing install in place, and launch the updated CLI automatically.

## `0.2.0`

- Added a lightweight syntax-aware parser for annotated test functions and invocations, improving FE065/FE075 without introducing third-party AST dependencies.
- Expanded the syntax-aware parser to carry function ranges and invocation locations, and reused it for FE076/FE077 so fallible-call checks handle multi-line chains and ignore comment/string noise.
- Added method-chain parsing to the syntax layer and rebuilt FE101 shell-injection detection on it, matching shell programs, flags, and dynamic arguments per `.arg(...)` call across lines.
- Rebuilt FE121/FE122 path-join detection on method-chain parsing so multi-line `.join(...)`/`.push(...)` calls are detected and comment/string noise is ignored.
- Moved FE080/FE081 regex literal extraction to statement-level constructor sites so multi-line `Regex::new(...)` calls are analyzed and non-constructor pattern text is ignored.
- Added FE078 (`test-without-assertions`) to catch test functions that call product code without asserting on behavior.
- Added FE079 (`ignored-product-call-result`) to flag bare statements that drop product-call results silently.
- Reworked the `lint` unused-binding module into a conventional `unused/` directory with shared FE063/FE064 scan plumbing and broader parser-boundary tests.

## `0.1.7`

- Split the `lint` unused-binding implementation into focused submodules for FE063/FE064 rule logic and shared statement/scope helpers without changing rule behavior.

## `0.1.6`

- Clarified in CLI help and docs that `--check-syntax` and `--max` are unsafe on untrusted repositories because they invoke Cargo on the target project.
- Deepened FE063 unused-variable detection to follow multi-line bindings, nested destructuring patterns, and common block-scoped shadow chains.

## `0.1.5`

- Hardened CLI terminal detection so help, intro text, and human-readable findings fall back to safer plain layouts on redirected output and legacy terminal environments.
- Updated human-readable findings to reflow into a stacked format on narrow terminals instead of forcing long one-line entries.
- Normalized human-readable finding paths to forward slashes so location lines stay consistent across Windows and Unix-like terminals.
- Tightened FE082 to inspect actual regex constructor arguments, reducing false positives from broad substring matching while still flagging runtime-built patterns.
- Refined FE083 to use nearby validation context and regex builder statements so multi-line validation code is checked without reintroducing search-style false positives.
- Improved regex helper parsing to ignore quantifier characters inside character classes when evaluating FE080 nested quantifiers.

## `0.1.4`

- Updated human CLI output so every finding line includes its own file path and line/column location instead of relying on grouped file headers.
- Tightened FE101 (`shell-string-injection`) to follow common multi-line `Command::new(...).arg(...).arg(...)` builder chains instead of only single-line shell command construction.
- Kept FE101 detection for environment-derived shell command input and documented the broader statement-aware behavior.
- Added FE076 to flag `unwrap`/`expect`-style calls outside test code.
- Added FE077 to flag error-erasing patterns such as `map_err(|_| ...)`.
- Added FE122 to flag archive extraction joins that use entry-derived path input without clear validation.
- Refined FE122 to treat `enclosed_name()`-style archive APIs and canonicalized extraction path prefix checks as explicit safe patterns.

## `0.1.3`

- Optimized scan fingerprint construction to write directly into a preallocated `String` with `push_str`, reducing temporary allocations in the cache-key path.
- Integrated benchmark mode into the main CLI via `fe203 --benchmark [N] <TARGET>`.
- Added benchmark help coverage in CLI tests so `--benchmark` stays visible in `--help` output.
- Improved Windows PATH handling so Fe203 prioritizes the current executable directory instead of only appending it, reducing stale-binary shadowing after upgrades.
- `fe203 --benchmark` now defaults to scanning `benchmarks/workload` when no target path is supplied.
- Improved FE101 to catch shell command construction fed from environment-variable-derived input.
- Refined FE083 validation regex detection using nearby validation context instead of flagging generic search-style matches.
- Strengthened secret heuristics with provider-specific token prefixes and stricter credential URL checks.
- Improved FE063 unused-variable detection for destructuring patterns and common shadow chains.

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
