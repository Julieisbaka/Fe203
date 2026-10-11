# `supply-chain` Rules

Checks for mutable remote references in GitHub Actions workflow files.
Workflow YAML files under `.github/workflows/` are scanned by default.

| ID | Severity | Name | Detects |
| ---- | ---------- | ---- | --------- |
| FE140 | high | `unpinned-workflow-reference` | remote action or reusable workflow references that are not pinned to a full commit SHA |

## FE140 — `unpinned-workflow-reference`

Flags remote `uses:` references pinned to a tag or branch, such as
`actions/checkout@v4` or `owner/repo/.github/workflows/build.yml@main`.
Pin each remote action or reusable workflow to a verified 40-character commit
SHA. Local actions and Docker-based actions are not checked by this rule.

This check analyzes the `uses:` lines in workflow YAML and does not resolve
references against GitHub; verify that a pinned SHA belongs to the intended
repository and release.

See [overview.md](overview.md) for the rule model and
[../suppressions.md](../suppressions.md) for how to suppress an individual
finding.
