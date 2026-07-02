//! General lint-style rules: clamp-like expressions, unused bindings,
//! and empty comments/docs.

use crate::finding::{Category, Finding, Severity};
use crate::rules::{FileContext, Rule};

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
        for (line_no, line) in ctx.lines() {
            let max_then_min = line.find(".max(").zip(line.find(").min("));
            let min_then_max = line.find(".min(").zip(line.find(").max("));
            let pos = match (max_then_min, min_then_max) {
                (Some((start, end)), _) if start < end => Some(start),
                (_, Some((start, end))) if start < end => Some(start),
                _ => None,
            };

            if let Some(column) = pos {
                findings.push(self.finding(
                    ctx,
                    line_no,
                    column + 1,
                    "manual clamp-like min/max chain found".to_string(),
                    line,
                ));
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
            let trimmed = line.trim_start();
            let empty = trimmed == "///" || trimmed == "//!";
            if empty {
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
}