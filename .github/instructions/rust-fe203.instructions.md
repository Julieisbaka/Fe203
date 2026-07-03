---
description: "Use when editing Rust source, scanner/rule logic, CLI parsing, config parsing, reporting, or tests in FE203."
applyTo: "src/**/*.rs,tests/**/*.rs"
---

Rust implementation instructions for FE203:

- Keep implementation std-only unless the user explicitly requests dependencies.
- Keep scanning heuristic and text-based by default; syntax-aware parsing is acceptable when explicitly requested or when it materially improves rule signal. Avoid heavyweight AST frameworks unless requested.
- Maintain stable rule registry behavior in src/rules/mod.rs.
- For new or changed rule behavior:
  - add or update unit tests in the rule module
  - update tests/pipeline.rs if end-to-end behavior changes
- Keep findings sorted and deterministic.
- Reuse existing helper functions and patterns before adding new abstractions.

Output and compatibility:
- If findings model fields change, update reporting and tests together.
- If CLI flags change, update parsing tests in src/cli.rs.
- Keep error messages specific and actionable.
