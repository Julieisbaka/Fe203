# `regex` Rules

Rules that flag risky or inefficient regex usage.

| ID | Severity | Detects |
|----|----------|---------|
| FE080 | warning | nested quantifiers like `(a+)+` |
| FE081 | info | suspicious regex wildcards / empty alternation |
| FE082 | high | dynamic regex construction from runtime input (`format!`, `concat!`, `.to_string()`, etc.) |
| FE083 | info | unanchored validation regex used with `is_match(`/`captures(` |

## Notes

- **FE083** was fixed to no longer trigger on ordinary `.find(` iterator/string
  calls. It now only flags string literals that actually look like a regex
  pattern, i.e. contain at least one regex metacharacter.

See [overview.md](overview.md) for the rule model and [../suppressions.md](../suppressions.md)
for how to suppress an individual finding.
