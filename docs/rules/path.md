# `path` Rules

Rules covering path traversal and untrusted path-join risks.

| ID | Severity | Name | Detects |
|----|----------|------|---------|
| FE120 | high | `path-traversal-literal` | a literal `..` path segment passed to `.join(`, `.push(`, or `PathBuf::from(` |
| FE121 | warning | `unsanitized-path-input` | a `.join(`/`.push(` call whose argument textually looks like untrusted input |

## FE120 — `path-traversal-literal`

Flags a literal `..` path segment passed directly to `.join(`, `.push(`, or
`PathBuf::from(`.

## FE121 — `unsanitized-path-input`

Flags a `.join(`/`.push(` call whose argument is not a string literal and
textually looks like untrusted input — i.e. it contains a keyword such as
`user`, `input`, `param`, `arg`, `request`, `req`, `untrusted`, `external`, or
`query`.

**Suggestion:** validate/canonicalize path segments derived from external
input before joining them onto a base directory.

See [overview.md](overview.md) for the rule model and [../suppressions.md](../suppressions.md)
for how to suppress an individual finding.
