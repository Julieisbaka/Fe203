# Roadmap

This roadmap tracks practical, scanner-focused improvements for FE203 after `0.1.0`.
Priorities are ordered by user impact, detection quality, and implementation risk.

## Current Focus (0.1.x)

1. Improve Rust correctness heuristics.
1. Expand high-signal security detections.
1. Keep output deterministic and CI-friendly.
1. Improve rule ergonomics without adding dependencies.

## Near-Term Work

### Detection quality

- Add unwrap/expect detection for non-test code paths.
- Add panic macro policy checks for library/public modules.
- Add wildcard error erasure checks (`map_err(|_| ...)`, similar patterns).
- Add dead suppression detection for stale `fe203-ignore` directives.
- Expand test quality checks beyond FE065 (assert-only tests with no product calls).

### Secret and credential coverage

- Expand token and credential URL heuristics with more provider patterns.
- Add suspicious inline private key and PEM block assignment checks.
- Add config-file secret hot spots (common key names in TOML/YAML/ENV files).

### Rule control and configuration

- Add optional severity policy presets for CI profiles.
- Add optional rule groups for strict vs baseline-compatible scans.
- Add tooling to report rules suppressed by config but still matching patterns.

## Mid-Term Work

### Safer scanning workflows

- Add baseline drift tooling (refresh, compare, audit).
- Add explicit scan summary deltas for CI regressions.
- Add workspace-level reporting for multi-crate scans.

### Path and shell hardening

- Expand shell detection coverage for interpreter chains and unsafe piping.
- Expand path traversal detection for extraction-style patterns.
- Add checks for path canonicalization mismatches before sensitive file access.

## Long-Term Investigation

- Lightweight source-to-sink correlation for high-risk flows (text-first heuristics only).
- Optional richer explanation output for AI-assisted triage workflows.
- Additional language-adjacent scans for mixed repositories while preserving Rust-first defaults.

## Success Criteria

- New rules must keep deterministic output ordering and stable rule IDs.
- Every behavior change must include tests and docs updates in the same change.
- High-severity rules should bias toward lower false positives, even with narrower initial coverage.
