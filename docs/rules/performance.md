# `performance` Rules

Heuristic checks for common avoidable allocations or repeated work. Findings
are suggestions to profile and review, not proof of a performance bottleneck.

| ID | Severity | Detects |
| ---- | ---------- | --------- |
| FE130 | info | cloning inside a loop |
| FE131 | warning | collecting an iterator only to iterate over the collection |
| FE132 | warning | compiling a regular expression inside a loop |
| FE133 | info | formatting a temporary string only to append it |

## FE130 — `clone-in-loop`

Flags `.clone()` calls in loops. Consider borrowing the value or moving
reusable work outside the loop when ownership permits.

## FE131 — `collect-before-iterate`

Flags an iterator collected into a temporary collection and immediately
iterated again. Continue the iterator chain directly when the intermediate
collection is not needed.

## FE132 — `regex-compiled-in-loop`

Flags common regex constructors inside loops. Compile the regex before the
loop and reuse it.

## FE133 — `format-then-push`

Flags `push_str(&format!(...))`, which creates a temporary string. Consider
writing directly into the destination buffer or appending its parts.

See [overview.md](overview.md) for the rule model and
[../suppressions.md](../suppressions.md) for how to suppress an individual
finding.
