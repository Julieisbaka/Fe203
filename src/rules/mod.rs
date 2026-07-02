//! Rule trait, registry, and shared text-matching helpers.
//!
//! To add a new rule:
//! 1. Implement [`Rule`] in a module under `src/rules/`.
//! 2. Register it in [`all_rules`].
//! 3. (Optional) Add a new [`Category`] if it doesn't fit an existing one.

pub mod debug_code;
pub mod lint;
pub mod regex_checks;
pub mod secrets;
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
    rules
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
