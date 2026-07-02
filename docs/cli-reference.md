# CLI Reference

## `fe203 [PATH]...`

Scans the given paths. If no path is provided, `.` is used.
Only `.rs` files are scanned by default, plus any extra files listed in
`[paths].include` inside `fe203.toml` (see [configuration.md](configuration.md)).

## `--config <FILE>`

Loads a config file instead of the default `./fe203.toml`.
The config is optional. If missing, Fe203 uses built-in defaults.

## `--rules <ID,ID>`

Enables only the listed rules. Example: `--rules FE001,FE080`.
This is applied on top of the config file.

## `--categories <A,B>`

Enables only the listed categories. Supported categories:

- `debug`
- `unsafe`
- `secrets`
- `lint`
- `regex`
- `shell`
- `path`

## `--list-rules`

Prints the auto-generated rule index from the built-in registry.
Useful for seeing stable rule IDs and descriptions without reading the source.

## `--explain <ID>`

Prints a single rule explanation, including:

- rule ID
- category
- severity
- description
- fix suggestion, when available

## `--init-config [FILE]`

Generates a starter `fe203.toml` file.
If the workspace contains a `.gitignore`, the generator copies safe exclusion
patterns into the new template so common build outputs stay excluded.

If no output file is supplied, Fe203 writes `./fe203.toml`.
The command exits with a non-zero status if the target file already exists.

## `--json`

Renders findings as JSON instead of the human-readable report.

## `--help`, `--version`

Print CLI usage or the current package version.

## Output Model

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
