# `secrets` Rules

Rules that flag hardcoded credential-like assignments. All rules in this
category have severity `high`.

| ID | Detects |
|----|---------|
| FE040 | hardcoded `password = "..."` |
| FE041 | hardcoded `api_key = "..."` |
| FE042 | hardcoded `secret = "..."` |

See [overview.md](overview.md) for the rule model and [../suppressions.md](../suppressions.md)
for how to suppress an individual finding.
