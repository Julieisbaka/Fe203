use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_rule_ignored, FileContext, Rule};

/// Detects empty Rust doc comments like `///` or `//!`.
pub struct EmptyDocCommentRule;

impl Rule for EmptyDocCommentRule {
    fn id(&self) -> &'static str {
        "FE061"
    }

    fn name(&self) -> &'static str {
        "empty-doc-comment"
    }

    fn description(&self) -> &'static str {
        "empty doc comments add noise without documenting behavior"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Write a short summary for the item or remove the empty doc comment.")
    }
    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: ///\nafter: /// Returns the parsed configuration.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["///", "//!"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            let trimmed = line.trim_start();
            let empty = trimmed == "///" || trimmed == "//!";
            if empty && !has_adjacent_doc_comment(ctx.content, line_no, trimmed) {
                let column = line.len() - trimmed.len() + 1;
                findings.push(self.finding(
                    ctx,
                    line_no,
                    column,
                    "empty doc comment found".to_string(),
                    line,
                ));
            }
        }
        findings
    }
}

/// Detects comments with no text, such as `//` or `/* */`.
pub struct EmptyCommentRule;

impl Rule for EmptyCommentRule {
    fn id(&self) -> &'static str {
        "FE062"
    }

    fn name(&self) -> &'static str {
        "empty-comment"
    }

    fn description(&self) -> &'static str {
        "empty comments add visual noise without explaining anything"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Remove the empty comment or replace it with a useful explanation.")
    }
    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: //\nafter: // Keep this branch for backward compatibility.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["//", "/*"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            let trimmed = line.trim_start();
            let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
            let is_empty_comment = trimmed == "//" || compact == "/**/";
            let is_doc_comment = trimmed.starts_with("///") || trimmed.starts_with("//!");
            if is_empty_comment && !is_doc_comment {
                let column = line.len() - trimmed.len() + 1;
                findings.push(self.finding(
                    ctx,
                    line_no,
                    column,
                    "empty comment found".to_string(),
                    line,
                ));
            }
        }
        findings
    }
}

/// True if the doc-comment line before or after `line_no` uses the same
/// prefix (`///` or `//!`) with real content, meaning this blank line is an
/// intentional paragraph break inside a larger doc-comment block rather
/// than a truly orphaned empty doc comment.
fn has_adjacent_doc_comment(content: &str, line_no: usize, prefix: &str) -> bool {
    let prev = if line_no >= 2 {
        content.lines().nth(line_no - 2).unwrap_or("").trim_start()
    } else {
        ""
    };
    let next = content.lines().nth(line_no).unwrap_or("").trim_start();
    prev.starts_with(prefix) || next.starts_with(prefix)
}
