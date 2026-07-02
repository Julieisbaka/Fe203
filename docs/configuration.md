# Configuration

Fe203 reads `fe203.toml` from the working directory (or pass `--config <file>`).
Everything is enabled by default; the config only needs to list what you change.

```toml
[rulesets]
# Enable or disable whole categories.
debug = true
unsafe = true
secrets = true
lint = true
regex = true
shell = true
path = true

[rules]
# Per-rule overrides win over category toggles.
FE003 = false   # allow dbg!()

[paths]
# Directory or file names skipped/included during discovery.
exclude = ["target", ".git"]
include = ["Cargo.toml"]
```

## Sections

- `[rulesets]` — toggles an entire category on or off.
- `[rules]` — toggles a single rule by ID, overriding its category setting.
- `[paths]` — `exclude` and `include` lists that adjust file discovery.

## Precedence

1. Per-rule toggle (`[rules]`)
2. Category toggle (`[rulesets]`)
3. Default (enabled)

CLI filters (`--rules`, `--categories`) are applied on top of the config.

## `--init-config` and `.gitignore`

`--init-config` seeds `[paths].exclude` from `.gitignore` when one is present
in the workspace, so common build outputs stay excluded without manual setup.

## Path-Matching Semantics

- A single-segment pattern (no `/`) matches any path component or the file's
  basename, e.g. `target` matches `target/` anywhere in the tree.
- Patterns containing `*` or `?` do glob matching. A single `*` does **not**
  cross a `/` directory boundary; use `**/` to cross directory boundaries.
- Patterns containing `/` are matched primarily against the path relative to
  the scan root, with a full-path fallback kept for backward compatibility.

## `build.rs` and `Cargo.toml`

`build.rs` is scanned automatically since it ends in `.rs`, like any other
Rust source file. `Cargo.toml` is not scanned by default — add it to
`[paths].include` to opt manifest files into the scan.
