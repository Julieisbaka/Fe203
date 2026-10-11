# `unsafe` Rules

Rules that flag `unsafe` code for manual review.

| ID    | Severity | Detects                                                |
|-------|----------|--------------------------------------------------------|
| FE020 | info     | `unsafe` usage (blocks/impls)                          |
| FE021 | warning  | `unsafe fn` declarations                               |
| FE022 | warning  | `transmute` and `transmute_copy` calls                 |
| FE023 | warning  | `mem::forget` calls that skip destructors              |
| FE024 | warning  | `mem::zeroed` calls that can create invalid values    |
| FE025 | warning  | mutable static variables                               |
| FE026 | warning  | raw-pointer dereferences                               |
| FE027 | warning  | unsafe blocks without a nearby safety explanation     |

See [overview.md](overview.md) for the rule model and [../suppressions.md](../suppressions.md)
for how to suppress an individual finding.
