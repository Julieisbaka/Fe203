//! Rule trait, registry, and shared text-matching helpers.
//!
//! To add a new rule:
//! 1. Implement [`Rule`] in a module under `src/rules/`.
//! 2. Register it in [`all_rules`].
//! 3. (Optional) Add a new [`Category`] if it doesn't fit an existing one.

pub mod debug_code;
pub mod lint;
pub mod path_safety;
pub mod regex_checks;
pub mod secrets;
pub mod shell;
pub mod unsafe_usage;

use std::path::Path;

use crate::finding::{Category, Finding, Severity};

/// Per-file context handed to each rule during a scan.
pub struct FileContext<'a> {
    pub path: &'a Path,
    pub content: &'a str,
}

impl<'a> FileContext<'a> {
    pub fn new(path: &'a Path, content: &'a str) -> Self {
        FileContext { path, content }
    }

    /// Iterates over (1-based line number, line text).
    pub fn lines(&self) -> impl Iterator<Item = (usize, &'a str)> {
        self.content.lines().enumerate().map(|(i, l)| (i + 1, l))
    }
}

/// A single, self-contained check that scans one file at a time.
pub trait Rule {
    /// Stable rule identifier, e.g. `FE001`.
    fn id(&self) -> &'static str;
    /// Short human-readable name.
    fn name(&self) -> &'static str;
    /// One-line description of what the rule detects and why it matters.
    fn description(&self) -> &'static str;
    fn category(&self) -> Category;
    fn severity(&self) -> Severity;
    /// Suggested fix/remediation shown with the finding, if any.
    fn suggestion(&self) -> Option<&'static str> {
        None
    }
    /// Scans a file and returns any findings.
    fn scan(&self, ctx: &FileContext) -> Vec<Finding>;

    /// Convenience constructor so rule impls stay terse.
    fn finding(&self, ctx: &FileContext, line: usize, column: usize, message: String, snippet: &str) -> Finding {
        Finding {
            rule_id: self.id(),
            rule_name: self.name(),
            category: self.category(),
            severity: self.severity(),
            file: ctx.path.to_path_buf(),
            line,
            column,
            message,
            snippet: snippet.trim().to_string(),
            suggestion: self.suggestion().map(str::to_string),
        }
    }
}

/// Returns every built-in rule, in stable ID order.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    rules.extend(debug_code::rules());
    rules.extend(unsafe_usage::rules());
    rules.extend(secrets::rules());
    rules.extend(lint::rules());
    rules.extend(regex_checks::rules());
    rules.extend(shell::rules());
    rules.extend(path_safety::rules());
    rules
}

/// Finds a built-in rule by ID.
pub fn rule_by_id<'a>(rules: &'a [Box<dyn Rule>], id: &str) -> Option<&'a dyn Rule> {
    rules.iter().map(|rule| rule.as_ref()).find(|rule| rule.id() == id)
}

/// Renders a generated rule index from the registry.
pub fn render_rule_index(rules: &[Box<dyn Rule>]) -> String {
    let mut out = String::new();
    out.push_str("Generated Fe203 rule index\n\n");
    for rule in rules.iter().map(|rule| rule.as_ref()) {
        out.push_str(&format!(
            "{:<6} {:<8} {:<8} {}\n      {}\n",
            rule.id(),
            rule.category().name(),
            rule.severity().name(),
            rule.name(),
            rule.description(),
        ));
        if let Some(suggestion) = rule.suggestion() {
            out.push_str(&format!("      help: {}\n", suggestion));
        }
        out.push('\n');
    }
    out
}

/// Renders a single rule explanation for `--explain`.
pub fn render_rule_explanation(rule: &dyn Rule) -> String {
    let mut out = String::new();
    out.push_str(&format!("{} — {}\n", rule.id(), rule.name()));
    out.push_str(&format!("Category: {}\n", rule.category().name()));
    out.push_str(&format!("Severity: {}\n", rule.severity().name()));
    out.push_str(&format!("Description: {}\n", rule.description()));
    if let Some(suggestion) = rule.suggestion() {
        out.push_str(&format!("Suggestion: {}\n", suggestion));
    }
    out
}

/// Returns true when the current line, the immediately preceding comment
/// line, or a whole-file `fe203-ignore-file` directive suppresses this rule.
pub(crate) fn is_rule_ignored(ctx: &FileContext, line_no: usize, rule_id: &str, rule_name: &str, category: Category) -> bool {
    line_has_ignore(ctx.content.lines().nth(line_no.saturating_sub(1)), rule_id, rule_name, category)
        || line_has_ignore(ctx.content.lines().nth(line_no.saturating_sub(2)), rule_id, rule_name, category)
        || content_has_file_ignore(ctx.content, rule_id, rule_name, category)
}

fn line_has_ignore(line: Option<&str>, rule_id: &str, rule_name: &str, category: Category) -> bool {
    let Some(line) = line else {
        return false;
    };
    let Some(comment) = extract_comment_text(line) else {
        return false;
    };
    let Some(rest) = comment.split_once("fe203-ignore") else {
        return false;
    };
    // A `fe203-ignore-file` directive is handled separately; don't also
    // treat it as a line-level ignore for whatever tokens follow `-file`.
    if rest.1.starts_with("-file") {
        return false;
    }
    ignore_tokens_match(rest.1, rule_id, rule_name, category)
}

/// Returns true if `content` contains a `fe203-ignore-file` directive
/// (anywhere, in any comment) matching the rule.
fn content_has_file_ignore(content: &str, rule_id: &str, rule_name: &str, category: Category) -> bool {
    for line in content.lines() {
        let Some(comment) = extract_comment_text(line) else {
            continue;
        };
        let Some(rest) = comment.split_once("fe203-ignore-file") else {
            continue;
        };
        if ignore_tokens_match(rest.1, rule_id, rule_name, category) {
            return true;
        }
    }
    false
}

fn ignore_tokens_match(rest: &str, rule_id: &str, rule_name: &str, category: Category) -> bool {
    rest.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .any(|item| {
            item.eq_ignore_ascii_case("all")
                || item.eq_ignore_ascii_case(rule_id)
                || item.eq_ignore_ascii_case(rule_name)
                || item.eq_ignore_ascii_case(category.name())
        })
}

fn extract_comment_text(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if let Some(pos) = trimmed.find("//") {
        return Some(&trimmed[pos + 2..]);
    }
    if let Some(start) = trimmed.find("/*") {
        let rest = &trimmed[start + 2..];
        if let Some(end) = rest.find("*/") {
            return Some(&rest[..end]);
        }
        return Some(rest);
    }
    None
}

/// True if the byte at `idx` starts a whole-word occurrence of `word`
/// (i.e. not part of a larger identifier).
pub(crate) fn is_word_boundary(line: &str, idx: usize, word_len: usize) -> bool {
    let before_ok = idx == 0
        || !line[..idx]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
    let after_ok = !line[idx + word_len..]
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_');
    before_ok && after_ok
}

/// Byte offsets of whole-word occurrences of `word` in `line`.
pub(crate) fn word_occurrences(line: &str, word: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut start = 0;
    while let Some(pos) = line[start..].find(word) {
        let idx = start + pos;
        if is_word_boundary(line, idx, word.len()) {
            out.push(idx);
        }
        start = idx + word.len();
    }
    out
}

/// True if the line is (or starts) a line comment. Cheap heuristic used to
/// cut false positives for code-pattern rules.
pub(crate) fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*")
}
