# `secrets` Rules

Rules that flag hardcoded credential-like assignments and common security
misconfigurations. Severity varies by rule.

| ID | Detects |
| ---- | --------- |
| FE040 | hardcoded `password = "..."` |
| FE041 | hardcoded `api_key = "..."` |
| FE042 | hardcoded `secret = "..."` |
| FE043 | hardcoded `token = "..."`-style assignments |
| FE044 | string literal URLs embedding credentials (for example `postgres://user:pass@host/db`) |
| FE045 | MD5/SHA-1 hash constructors and digest calls |
| FE046 | TLS certificate or hostname validation explicitly disabled |
| FE047 | PEM private-key markers embedded in source |

FE045 is a heuristic warning: MD5 and SHA-1 may be suitable for non-security
uses, but not where collision resistance is required. FE046 only reports the
common builder methods when their argument is the literal `true`. FE047 detects
PEM markers in non-comment source lines; remove and rotate any exposed key.

See [overview.md](overview.md) for the rule model and [../suppressions.md](../suppressions.md)
for how to suppress an individual finding.
