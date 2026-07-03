# `shell` Rules

Rules covering shell command construction risks.

| ID    | Severity | Name                     | Detects                                                                                                 |
|-------|----------|--------------------------|---------------------------------------------------------------------------------------------------------|
| FE100 | info     | `command-execution`      | presence of `Command::new(` / `std::process::Command::new(`                                             |
| FE101 | high     | `shell-string-injection` | a shell interpreter invoked with a shell flag and a dynamically built or environment-fed command string |

## FE100 — `command-execution`

Flags any use of `Command::new(` or `std::process::Command::new(` as a review
flag. This does not imply a problem by itself — it highlights code paths worth
a closer look.

## FE101 — `shell-string-injection`

Flags a command builder where:

1. A shell interpreter (`sh`, `bash`, `cmd`, `cmd.exe`, `powershell`, `pwsh`)
   is invoked with a shell flag (`-c`, `/c`, `/C`, `-Command`), **and**
2. The command string in that statement is built dynamically (`format!`,
   `concat!`, `.to_string()`, `push_str`, or string `+` concatenation), or fed
   from environment-derived input.

Changed in `0.1.4`: the rule now follows common multi-line builder chains such as:

```rust
Command::new("sh")
    .arg("-c")
    .arg(format!("echo {}", user));
```

Changed in `0.2.0`: detection is built on syntax-aware method-chain parsing
instead of flattened statement text, so shell program names, flags, and
dynamic arguments are matched per `.arg(...)` call and shell-like text inside
comments or unrelated string literals no longer triggers the rule.

**Suggestion:** prefer passing arguments individually via `.arg()` instead of
invoking a shell with an interpolated string.

See [overview.md](overview.md) for the rule model and [../suppressions.md](../suppressions.md)
for how to suppress an individual finding.
