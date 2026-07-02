# Contributing to Fe203

Fe203 is intentionally small and modular. The preferred workflow is to make
the change easy to review, keep the rule logic local, and add a focused test.

## Before You Start

- Run `cargo test` before changing anything substantial.
- Use the existing `Rule` trait and `all_rules()` registry for new checks.
- Keep new behavior text-first unless there is a clear reason to add more parsing machinery.

## Adding a Rule

1. Add a small module under `src/rules/`.
2. Implement the `Rule` trait.
3. Register the rule in `src/rules/mod.rs`.
4. Add at least one unit test and, if relevant, one integration fixture.

Rule IDs should use the short `FE###` style. See [rules/overview.md](rules/overview.md).

## Tests

- Unit tests live next to the implementation.
- End-to-end fixtures live in `tests/`.
- Prefer narrow fixtures that demonstrate one rule at a time.

## Documentation

Docs live under `docs/` as multiple small topic files rather than one large
file, plus one file per rule category under `docs/rules/`. The changelog and
this contributing guide also live in `docs/` (`docs/changelog.md`,
`docs/contributing.md`) rather than at the repo root.

When you add a command, config option, or rule, update the relevant doc file
alongside the code change:

- CLI flags → [cli-reference.md](cli-reference.md)
- config format → [configuration.md](configuration.md)
- suppression behavior → [suppressions.md](suppressions.md)
- a new/changed rule → the matching file under [rules/](rules/overview.md)

## Pull Requests

- Keep changes focused.
- Update docs when you add a command or change rule behavior.
- If you add a new suppression or config feature, include a fixture that proves the exact behavior.
