# `debug` Rules

Rules that flag debug-only or unfinished-code macros. All rules in this
category have severity `warning`.

| ID | Detects |
|----|---------|
| FE001 | `todo!()` |
| FE002 | `unimplemented!()` |
| FE003 | `dbg!()` |
| FE004 | `panic!()` |

See [overview.md](overview.md) for the rule model and [../suppressions.md](../suppressions.md)
for how to suppress an individual finding.
