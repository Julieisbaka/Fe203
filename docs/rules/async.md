# `async` Rules

Rules for common async/concurrency hazards. These checks use lightweight
source analysis and may need manual review.

| ID | Severity | Detects |
| ---- | ---------- | --------- |
| FE110 | warning | blocking standard-library calls inside an `async fn` |
| FE111 | warning | synchronous mutex guards used across `.await` |
| FE112 | info | spawned task handles that are neither retained nor awaited |

## FE110 — `blocking-call-in-async`

Flags common blocking calls such as synchronous filesystem operations or
`std::thread::sleep` inside an async function. Prefer an async API or move
blocking work to an appropriate blocking-task facility.

## FE111 — `lock-held-across-await`

Flags a synchronous mutex guard that remains in use after an `.await`. Keep
the guard's scope short so it is dropped before awaiting, or use an async-aware
lock when appropriate.

## FE112 — `detached-task-handle`

Flags recognized spawned tasks whose handle is dropped immediately. Store and
await the handle when completion or task failure matters; intentionally
detached tasks may be acceptable when their lifecycle is explicitly managed.

See [overview.md](overview.md) for the rule model and
[../suppressions.md](../suppressions.md) for how to suppress an individual
finding.
