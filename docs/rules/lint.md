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
| FE077 | warning | error-erasing patterns like `map_err(\|_\| ...)` |
| FE078 | warning | test function that calls product code but never asserts on behavior |
| FE079 | info | bare statement that calls product code and silently drops the returned value |

## Notes

- **FE060**: Changed in `0.0.2`. Detected across multi-line method chains, not just when the
  chain appears on a single line.
- **FE063**: Changed in `0.1.6`. Now follows multi-line `let` statements, nested destructuring
  patterns, and same-name shadow chains across inner blocks. It is still
  heuristic text analysis, so macro-generated bindings and more complex
  control-flow-sensitive cases can still be missed.
- **FE065** and **FE075**: Changed in `0.2.0`. They now use lightweight
  syntax-aware parsing for annotated test functions and invocation detection,
  which reduces noise from comments, string literals, and brace-like text in
  test bodies without introducing a full Rust AST dependency.
- **FE076** and **FE077**: Changed in `0.2.0`. They now reuse the same
  syntax-aware invocation parser, which improves multi-line detection and avoids
  matching `.unwrap()`/`.expect(...)`-style text inside comments or string
  literals.
- **FE078**: Added in `0.2.0`. Flags smoke-test style functions that call
  product code but never assert on outputs or effects.
- **FE079**: Added in `0.2.0`. Flags bare statements like `crate::run(x);`
  where a product-code call result is silently dropped. Bind with `let _ =`
  to mark an intentional drop.

See [overview.md](overview.md) for the rule model and [../suppressions.md](../suppressions.md)
for how to suppress an individual finding.
