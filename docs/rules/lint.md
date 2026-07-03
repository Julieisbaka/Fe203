# `lint` Rules

General code-quality lint rules.

| ID | Severity | Detects |
| ---- | ---------- | --------- |
| FE060 | info | manual clamp-like `.max(...).min(...)` / `.min(...).max(...)` chains |
| FE061 | warning | empty doc comments (`///` / `//!`) |
| FE062 | info | empty comments (`//` / `/* */`) |
| FE063 | warning | unused local variables |
| FE064 | warning | unused constants |
| FE065 | warning | test code with `#[test]`/async test attributes that does not reference product code |
| FE066 | info | stale `fe203-ignore`/`fe203-ignore-file` rule IDs that do not match any finding in the file |
| FE075 | warning | test function with assert-only logic and no product-code call/reference |
| FE076 | warning | `unwrap`/`expect`-style calls outside test code |
| FE077 | warning | error-erasing patterns like `map_err(|_| ...)` |

## Notes

- **FE060** is detected across multi-line method chains, not just when the
  chain appears on a single line.

See [overview.md](overview.md) for the rule model and [../suppressions.md](../suppressions.md)
for how to suppress an individual finding.
