# CLI Reference

## `fe203 [PATH]...`

Scans the given paths. If no path is provided, Fe203 prints an intro/quick-start
screen and exits.
Only `.rs` files are scanned by default, plus any extra files listed in
`[paths].include` inside `fe203.toml` (see [configuration.md](configuration.md)).

On Windows, when run from a downloaded release binary, Fe203 attempts a
one-time user `PATH` registration for its executable directory.

Set `FE203_NO_AUTO_PATH=1` to disable this behavior.

## `--config <FILE>`

Loads a config file instead of the default `./fe203.toml`.
The config is optional. If missing, Fe203 uses built-in defaults.

Also supports `--config=FILE`.

## `--rules <ID,ID>`

Enables only the listed rules. Example: `--rules FE001,FE080`.
This is applied on top of the config file.

- Short alias: `-r`
- Supports `--rules=FE001,FE080`
- Can be repeated; values are merged in argument order

## `--categories <A,B>`

Enables only the listed categories. Supported categories:

- `debug`
- `unsafe`
- `secrets`
- `lint`
- `regex`
- `shell`
- `path`

- Short alias: `-g`
- Supports `--categories=debug,secrets`
- Can be repeated; values are merged in argument order

## `--list-rules`

Prints the auto-generated rule index from the built-in registry.
Useful for seeing stable rule IDs and descriptions without reading the source.

Short alias: `-l`.

## `--explain <ID>`

Prints a single rule explanation, including:

- rule ID
- category
- severity
- description
- fix suggestion, when available

Short alias: `-x`. Also supports `--explain=ID`.

## `--init-config [FILE]`

Generates a starter `fe203.toml` file.
If the workspace contains a `.gitignore`, the generator copies safe exclusion
patterns into the new template so common build outputs stay excluded.

If no output file is supplied, Fe203 writes `./fe203.toml`.
The command exits with a non-zero status if the target file already exists.

## `--json`

Renders findings as JSON instead of the human-readable report.

Short alias: `-j`.

## `--sarif`

Renders findings as SARIF v2.1.0 JSON for CI/code-scanning systems.

`--json` and `--sarif` are mutually exclusive.

Short alias: `-s`.

## `--pretty`

Pretty-prints machine-readable output for readability.

- Valid only with `--json` or `--sarif`
- Does not affect human-readable output mode

Short alias: `-p`.

## `--baseline <FILE>`

Loads a baseline file and suppresses findings that already exist in it.

Baseline format is line-based:

```text
RULE_ID|path/to/file.rs|line|column|message
```

Lines starting with `#` are ignored as comments.

Short alias: `-b`. Also supports `--baseline=FILE`.

## `--init-baseline [FILE]`

Writes a baseline from the current scan results and exits.

If no output file is supplied, Fe203 writes `./fe203.baseline`.
The command exits with a non-zero status if the target file already exists.

Short alias: `-B`. Also supports `--init-baseline=FILE`.

## `--check-syntax`

Runs an opt-in `cargo check --quiet` pass before scanning.

- Syntax checking is disabled by default.
- Checks run only for scan targets that resolve to a directory containing
  `Cargo.toml` (or a `Cargo.toml` file target).
- If no matching Cargo target is found, Fe203 prints a warning and continues.
- If `cargo check` fails, Fe203 exits with code `2`.

## `--max`

Runs Fe203 in maximum validation mode before scanning:

- runs `cargo check --quiet` automatically
- runs `cargo test --quiet` automatically
- enables all built-in rules regardless of `fe203.toml` toggles or CLI rule/category filters
- bypasses cheap rule prefiltering so every enabled rule runs against every scanned file

`--max` is useful for strict CI checks or deep local validation sweeps.

## `--benchmark [N]`

Runs the CLI repeatedly against a target folder and reports timing stats.

- `N` is optional and defaults to `5`
- benchmark mode requires a target path argument
- each iteration runs one full CLI scan of the target folder
- benchmark child runs suppress normal scan output and only timing stats are printed

Examples:

```sh
fe203 --benchmark benchmarks/workload
fe203 --benchmark 10 benchmarks/workload
```

## Scan Pipeline Notes

Fe203 builds a per-file scan index and uses cheap rule signatures to skip rule
evaluation when a file clearly cannot match.

This optimization is enabled by default and reduces CPU cost for larger scans.
`--max` disables this prefilter stage to force full rule evaluation.

Fe203 also maintains an incremental scan cache at `.fe203/scan-cache.v1` in the
current workspace and reuses findings for unchanged files when the scan
fingerprint is unchanged.

Set `FE203_NO_CACHE=1` to disable incremental cache reads/writes.

## `--help`, `--version`

Print CLI usage or the current package version.

Help output adapts to terminal capabilities:

- narrow terminals use wrapped option descriptions
- `TERM=dumb` or `FE203_ASCII=1` uses ASCII-safe headings/symbols

## Output Model

In human-readable mode, Fe203 prints scan status/progress lines to `stderr`:

- discovery start/completion
- scan start/completion and total finding count

Set `FE203_NO_PROGRESS=1` to disable these status lines.

Each finding includes:

- `rule_id`
- `rule_name`
- `category`
- `severity`
- `file`
- `line`
- `column`
- `message`
- `snippet`
- `suggestion`

Human output also prints a `help:` line when the rule provides a suggestion.

## Exit Codes

- `0` = clean
- `1` = findings reported
- `2` = usage/config error
