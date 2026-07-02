//! General lint-style rules: clamp-like expressions, unused bindings,
//! and empty comments/docs.
// fe203-ignore-file FE060, FE061, FE062

use std::collections::HashSet;

use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_rule_ignored, FileContext, Rule};

/// Detects manual clamp chains like `value.max(min).min(max)`.
pub struct ClampLikePatternRule;

impl Rule for ClampLikePatternRule {
    fn id(&self) -> &'static str {
        "FE060"
    }

    fn name(&self) -> &'static str {
        "manual-clamp"
    }

    fn description(&self) -> &'static str {
        "manual clamp-like min/max chains are harder to read than `.clamp(...)`"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Replace the chained min/max expression with `.clamp(lower, upper)` when the bounds are known.")
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for (start_pat, end_pat) in [(".max(", ".min("), (".min(", ".max(")] {
            let mut search_start = 0;
            while let Some(start_rel) = ctx.content[search_start..].find(start_pat) {
                let start_idx = search_start + start_rel;
                let window_end = (start_idx + 240).min(ctx.content.len());
                let window = &ctx.content[start_idx + start_pat.len()..window_end];
                if let Some(end_rel) = window.find(end_pat) {
                    let end_idx = start_idx + start_pat.len() + end_rel;
                    if seen.insert((start_idx, end_idx)) {
                        let (line_no, column) = line_col_at(ctx.content, start_idx);
                        if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                            search_start = start_idx + start_pat.len();
                            continue;
                        }
                        let snippet = snippet_for_range(ctx.content, start_idx, end_idx + end_pat.len());
                        findings.push(self.finding(
                            ctx,
                            line_no,
                            column,
                            "manual clamp-like min/max chain found".to_string(),
                            &snippet,
                        ));
                    }
                    search_start = start_idx + start_pat.len();
                } else {
                    search_start = start_idx + start_pat.len();
                }
            }
        }
        findings
    }
}

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

/// Detects local variables that appear to be declared but never used.
pub struct UnusedVariableRule;

impl Rule for UnusedVariableRule {
    fn id(&self) -> &'static str {
        "FE063"
    }

    fn name(&self) -> &'static str {
        "unused-variable"
    }

    fn description(&self) -> &'static str {
        "unused variables are a sign of dead code or a missed refactor"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Remove the variable or prefix it with an underscore if it is intentionally unused.")
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            if let Some(name) = parse_let_binding_name(line) {
                if is_used_once_in_content(ctx.content, &name) {
                    if let Some(column) = line.find(&name).map(|idx| idx + 1) {
                        findings.push(self.finding(
                            ctx,
                            line_no,
                            column,
                            format!("unused variable `{name}`"),
                            line,
                        ));
                    }
                }
            }
        }
        findings
    }
}

/// Detects constants that appear to be declared but never used.
pub struct UnusedConstantRule;

impl Rule for UnusedConstantRule {
    fn id(&self) -> &'static str {
        "FE064"
    }

    fn name(&self) -> &'static str {
        "unused-constant"
    }

    fn description(&self) -> &'static str {
        "unused constants often indicate dead code or stale configuration"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Remove the constant or use it at every call site that needs it.")
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            if let Some(name) = parse_const_name(line) {
                if is_used_once_in_content(ctx.content, &name) {
                    if let Some(column) = line.find(&name).map(|idx| idx + 1) {
                        findings.push(self.finding(
                            ctx,
                            line_no,
                            column,
                            format!("unused constant `{name}`"),
                            line,
                        ));
                    }
                }
            }
        }
        findings
    }
}

/// All lint-style rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ClampLikePatternRule),
        Box::new(EmptyDocCommentRule),
        Box::new(EmptyCommentRule),
        Box::new(UnusedVariableRule),
        Box::new(UnusedConstantRule),
    ]
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

fn line_col_at(content: &str, idx: usize) -> (usize, usize) {
    let prefix = &content[..idx];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rfind('\n')
        .map(|pos| prefix[pos + 1..].chars().count() + 1)
        .unwrap_or_else(|| prefix.chars().count() + 1);
    (line, column)
}

fn snippet_for_range(content: &str, start: usize, end: usize) -> String {
    let start = start.saturating_sub(20);
    let end = (end + 20).min(content.len());
    content[start..end].trim().replace('\n', " ")
}

fn parse_let_binding_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let mut rest = trimmed.strip_prefix("let ")?;
    rest = rest.trim_start();
    if let Some(after_mut) = rest.strip_prefix("mut ") {
        rest = after_mut.trim_start();
    }
    let mut name = String::new();
    for ch in rest.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            name.push(ch);
        } else {
            break;
        }
    }
    if name.is_empty() || name.starts_with('_') {
        return None;
    }
    let tail = rest[name.len()..].trim_start();
    match tail.chars().next() {
        Some(':' | '=' | ';') => Some(name),
        Some('(' | '{' | '[' | ',') | None => None,
        _ => None,
    }
}

fn parse_const_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = if let Some(after_pub) = trimmed.strip_prefix("pub ") {
        after_pub.trim_start()
    } else {
        trimmed
    };
    let rest = rest.strip_prefix("const ")?;
    let mut name = String::new();
    for ch in rest.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            name.push(ch);
        } else {
            break;
        }
    }
    if name.is_empty() || name.starts_with('_') {
        return None;
    }
    let tail = rest[name.len()..].trim_start();
    match tail.chars().next() {
        Some(':' | '=') => Some(name),
        _ => None,
    }
}

fn is_used_once_in_content(content: &str, name: &str) -> bool {
    let mut count = 0;
    let mut start = 0;
    while let Some(pos) = content[start..].find(name) {
        count += 1;
        if count > 1 {
            return false;
        }
        start += pos + name.len();
    }
    count == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan_all(content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(Path::new("test.rs"), content);
        rules().iter().flat_map(|r| r.scan(&ctx)).collect()
    }

    #[test]
    fn detects_manual_clamp_chain() {
        let findings = scan_all("value.max(min).min(max);\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE060");
    }

    #[test]
    fn detects_multiline_clamp_chain() {
        let findings = scan_all("value\n    .max(min)\n    .min(max);\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE060");
    }

    #[test]
    fn detects_empty_doc_comments_and_empty_comments() {
        let findings = scan_all("///\n//!\n//\n/* */\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE061", "FE061", "FE062", "FE062"]);
    }

    #[test]
    fn ignores_non_empty_comments() {
        let findings = scan_all("/// useful\n// not empty\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_unused_variable_and_constant() {
        let findings = scan_all(
            "fn f() {\n    let temp = 1;\n    const MAX_RETRY: usize = 3;\n    println!(\"{}\", temp);\n}\n",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE064"]);
    }

    #[test]
    fn flags_simple_unused_variable() {
        let findings = scan_all("fn f() {\n    let unused = 1;\n}\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE063");
    }

    #[test]
    fn respects_ignore_comments() {
        let findings = scan_all("// fe203-ignore FE060\nvalue.max(min).min(max);\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_blank_doc_line_used_as_paragraph_break() {
        let findings = scan_all("//! Summary line.\n//!\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_truly_isolated_empty_doc_comment() {
        let findings = scan_all("///\nfn f() {}\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE061");
    }
}