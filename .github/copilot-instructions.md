# FE203 Copilot Instructions

Project goals:
- Keep FE203 fast, std-only, and text-first.
- Preserve stable rule IDs and deterministic behavior.
- Keep docs and CLI behavior aligned.

General engineering rules:
- Use Rust 2021 and the existing module layout.
- Do not add third-party dependencies unless explicitly requested.
- Prefer small, focused edits over broad refactors.
- Preserve existing naming and output formats unless the task requires a change.
- Add or update tests for behavior changes in rules, parsing, reporting, or scanning.

Documentation update policy:
- When CLI flags, output formats, config keys, or behavior changes, update docs in the same change.
- Keep these files consistent when relevant: docs/cli-reference.md, docs/configuration.md, docs/getting-started.md, docs/changelog.md, docs/roadmap.md, README.md.
- Include concise, practical examples for user-facing features.

Styling and writing guidance:
- Keep user-facing text concise and instructional.
- Keep rule descriptions and suggestions short and actionable.
- Use plain, consistent headings in docs.
- Keep code comments minimal; only explain non-obvious logic.

Safety and compatibility:
- Never remove or reuse an existing FE rule ID.
- Keep exit code semantics stable unless explicitly requested.
- Avoid changing JSON field names or SARIF schema fields without updating docs and tests.
