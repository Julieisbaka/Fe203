---
description: "Use when preparing a release for FE203, including version bump, changelog entries, and doc synchronization."
applyTo: "Cargo.toml,README.md,docs/**/*.md"
---

Release workflow instructions for FE203:

- Keep package version, changelog, and user-facing docs synchronized.
- For each release:
  - update version in Cargo.toml
  - add a new section in docs/changelog.md
  - update docs/roadmap.md to reflect completed roadmap items
  - update README.md or docs/getting-started.md when install or CLI behavior changed
- Keep release notes concise and user-visible.
- Ensure CLI examples in docs reflect current flags and output behavior.
- Do not remove historical changelog entries.

Validation checklist for release edits:
- Cargo.toml version matches the latest changelog heading.
- New features in code are documented in the appropriate docs pages.
- Deprecated or completed roadmap items are adjusted in docs/roadmap.md.
