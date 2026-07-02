//! Unsafe-usage rules: `unsafe` blocks/exprs and `unsafe fn` declarations.
// fe203-ignore-file FE020

use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_comment_line, is_rule_ignored, word_occurrences, FileContext, Rule};

/// Whether the `unsafe` keyword at `idx` is followed by `fn`.
fn is_unsafe_fn(line: &str, idx: usize) -> bool {
    let rest = line[idx + "unsafe".len()..].trim_start();
    rest == "fn" || rest.starts_with("fn ") || rest.starts_with("fn(")
}

/// Detects `unsafe` usage that is not an `unsafe fn` declaration
/// (blocks, impls, traits).
pub struct UnsafeUsageRule;

impl Rule for UnsafeUsageRule {
    fn id(&self) -> &'static str {
        "FE020"
    }
    fn name(&self) -> &'static str {
        "unsafe-usage"
    }
    fn description(&self) -> &'static str {
        "`unsafe` code bypasses Rust's safety guarantees and deserves review"
    }
    fn category(&self) -> Category {
        Category::Unsafe
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some("Isolate unsafe code behind a safe abstraction and document the safety invariants.")
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            if is_comment_line(line) {
                continue;
            }
            for idx in word_occurrences(line, "unsafe") {
                if !is_unsafe_fn(line, idx) {
                    findings.push(self.finding(
                        ctx,
                        line_no,
                        idx + 1,
                        "`unsafe` usage found".to_string(),
                        line,
                    ));
                }
            }
        }
        findings
    }
}

/// Detects `unsafe fn` declarations.
pub struct UnsafeFnRule;

impl Rule for UnsafeFnRule {
    fn id(&self) -> &'static str {
        "FE021"
    }
    fn name(&self) -> &'static str {
        "unsafe-fn"
    }
    fn description(&self) -> &'static str {
        "`unsafe fn` pushes safety obligations onto every caller"
    }
    fn category(&self) -> Category {
        Category::Unsafe
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some("Prefer a safe function if possible, or document the caller obligations in a Safety section.")
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            if is_comment_line(line) {
                continue;
            }
            for idx in word_occurrences(line, "unsafe") {
                if is_unsafe_fn(line, idx) {
                    findings.push(self.finding(
                        ctx,
                        line_no,
                        idx + 1,
                        "`unsafe fn` declaration found".to_string(),
                        line,
                    ));
                }
            }
        }
        findings
    }
}

/// All unsafe-usage rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(UnsafeUsageRule), Box::new(UnsafeFnRule)]
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
    fn detects_unsafe_block() {
        let findings = scan_all("fn f() {\n    unsafe { do_thing() }\n}\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE020");
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn detects_unsafe_fn_separately() {
        // fe203-ignore FE021
        let findings = scan_all("pub unsafe fn danger() {}\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE021");
    }

    #[test]
    fn ignores_comments_and_identifiers() {
        // fe203-ignore FE021
        let findings = scan_all("// unsafe fn in a comment\nlet not_unsafe_here = 1;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn respects_ignore_comments() {
        let findings = scan_all("// fe203-ignore FE020\nunsafe { do_thing() }\n");
        assert!(findings.is_empty());
    }
}
