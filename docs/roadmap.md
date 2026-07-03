# Roadmap

Suggested next features for future releases:

- `Result`/`Option` handling heuristics (`unwrap`, `expect`, ignored errors)
- FFI boundary review
- serde/deserialization safety checks
- per-directory rule profiles
- baseline drift tools (refresh/diff/audit)

## New Ideas Following the Shell and Path Rule Families

Now that the `shell` ([rules/shell.md](rules/shell.md)) and `path`
([rules/path.md](rules/path.md)) rule families exist, related follow-up ideas
include:

- expanding shell heuristics to cover more shells/interpreters and
  pipe-based injection
- expanding path rules to cover symlink-following and archive/zip-slip
  extraction checks
- a possible future taint-tracking pass connecting untrusted input sources to
  these new sinks
