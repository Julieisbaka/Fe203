# Suppressions

Fe203 supports two comment-based suppression mechanisms. Both are line/file
text checks, not AST-aware, so they should be used for deliberate fixtures or
accepted false positives — not as a substitute for fixing real findings.

Both mechanisms accept a comma/whitespace-separated list of tokens, where each
token can be:

- a rule ID, such as `FE080`
- a rule name, such as `nested-regex-quantifier`
- a category, such as `regex`
- the literal `all`

## Line-Level: `fe203-ignore`

Place `// fe203-ignore <tokens>` on the finding's own line, or on the line
immediately above it.

```rust
// fe203-ignore FE080
let re = Regex::new(r"(a+)+$");

let re = Regex::new(r"(a+)+$"); // fe203-ignore FE080
```

## File-Level: `fe203-ignore-file`

Place `// fe203-ignore-file <tokens>` anywhere in a file (conventionally near
the top) to suppress the matching rule(s) for the **entire file**.

```rust
// fe203-ignore-file secrets,FE060

fn example() {
    let password = "hardcoded-for-test-fixture"; // not flagged in this file
}
```

## Notes

- These checks are line/file-oriented text checks, not AST-aware.
- Use them for deliberate test fixtures or genuinely accepted false positives,
  not to silence findings that should instead be fixed.
- See [rules/overview.md](rules/overview.md) for rule IDs, names, and categories.
