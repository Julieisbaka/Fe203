# `regex` Rules

Rules that flag risky or inefficient regex usage.

| ID | Severity | Detects |
|----|----------|---------|
| FE080 | warning | nested quantifiers like `(a+)+` |
| FE081 | info | suspicious regex wildcards / empty alternation |
| FE082 | high | dynamic regex construction from runtime input or non-literal pattern expressions |
| FE083 | info | unanchored validation regex used with `is_match(`/`captures(` |

## Notes

- **FE082** now inspects the actual `Regex::new(...)` or `RegexBuilder::new(...)`
  argument expression instead of relying on broad substring matches. Fixed
  literal expressions, including compile-time `concat!(...)` of string
  literals, are ignored; runtime-built expressions are still flagged.
- **FE083** was fixed to no longer trigger on ordinary `.find(` iterator/string
  calls. It now only flags string literals that actually look like a regex
  pattern, i.e. contain at least one regex metacharacter.
- **FE083** also looks at nearby regex builder statements, so validation-style
  code split across multiple lines is still checked while search-oriented names
  such as `search_re` stay suppressed.

See [overview.md](overview.md) for the rule model and [../suppressions.md](../suppressions.md)
for how to suppress an individual finding.
