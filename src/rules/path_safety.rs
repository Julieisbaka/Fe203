//! Path-safety rules: literal traversal segments and untrusted-looking
//! path joins.
// fe203-ignore-file FE120, FE121

use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_rule_ignored, FileContext, Rule};

const JOIN_CALLS: &[&str] = &[".join(", ".push("];
const UNTRUSTED_KEYWORDS: &[&str] = &[
    "user",
    "input",
    "param",
    "arg",
    "request",
    "req",
    "untrusted",
    "external",
    "query",
];

/// Detects a literal `..` path segment passed to `.join(`, `.push(`, or
/// `PathBuf::from(`.
pub struct PathTraversalLiteralRule;

impl Rule for PathTraversalLiteralRule {
    fn id(&self) -> &'static str {
        "FE120"
    }

    fn name(&self) -> &'static str {
        "path-traversal-literal"
    }

    fn description(&self) -> &'static str {
        "a literal `..` path segment can escape the intended base directory"
    }

    fn category(&self) -> Category {
        Category::Path
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Reject or normalize path segments containing `..` before joining them onto a base directory.")
    }
    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: base.join(\"../secret\")\nafter: if segment.contains(\"..\") { return Err(e); }")
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            for call in JOIN_CALLS {
                for (column, arg) in call_arguments(line, call) {
                    if arg.contains("..") && (arg.contains('"') || arg.contains('\'')) {
                        findings.push(self.finding(
                            ctx,
                            line_no,
                            column,
                            format!(
                                "literal `..` path segment passed to `{}`",
                                call.trim_end_matches('(')
                            ),
                            line,
                        ));
                    }
                }
            }
            if let Some(idx) = line.find("PathBuf::from(") {
                let rest = &line[idx + "PathBuf::from(".len()..];
                if let Some(end) = rest.find(')') {
                    let arg = &rest[..end];
                    if arg.contains("..") && arg.contains('"') {
                        findings.push(self.finding(
                            ctx,
                            line_no,
                            idx + 1,
                            "literal `..` path segment passed to `PathBuf::from`".to_string(),
                            line,
                        ));
                    }
                }
            }
        }
        findings
    }
}

/// Detects `.join(`/`.push(` calls whose argument looks like untrusted
/// input based on common naming keywords.
pub struct UnsanitizedPathInputRule;

impl Rule for UnsanitizedPathInputRule {
    fn id(&self) -> &'static str {
        "FE121"
    }

    fn name(&self) -> &'static str {
        "unsanitized-path-input"
    }

    fn description(&self) -> &'static str {
        "joining a path with a variable that looks like untrusted input can allow path traversal"
    }

    fn category(&self) -> Category {
        Category::Path
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Validate or canonicalize path segments derived from external input before joining them onto a base directory.")
    }
    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: base.join(user_input)\nafter: base.join(sanitize_segment(user_input)?)")
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            for call in JOIN_CALLS {
                for (column, arg) in call_arguments(line, call) {
                    let trimmed = arg.trim();
                    if trimmed.starts_with('"') || trimmed.is_empty() {
                        continue;
                    }
                    let lower = trimmed.to_lowercase();
                    if UNTRUSTED_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
                        findings.push(self.finding(
                            ctx,
                            line_no,
                            column,
                            format!(
                                "`{}` call joins a path with untrusted-looking input `{}`",
                                call.trim_end_matches('('),
                                trimmed
                            ),
                            line,
                        ));
                    }
                }
            }
        }
        findings
    }
}

/// All path-safety rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(PathTraversalLiteralRule),
        Box::new(UnsanitizedPathInputRule),
    ]
}

/// Returns (1-based column of the call start, argument text) for each
/// occurrence of `call` (e.g. `.join(`) in `line`, using naive paren-depth
/// counting to find the matching close paren.
fn call_arguments(line: &str, call: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut start = 0;
    while let Some(pos) = line[start..].find(call) {
        let call_idx = start + pos;
        let args_start = call_idx + call.len();
        let mut depth = 1i32;
        let mut end = None;
        for (offset, ch) in line[args_start..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(args_start + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(end) = end {
            found.push((call_idx + 1, line[args_start..end].to_string()));
            start = end + 1;
        } else {
            start = args_start;
        }
    }
    found
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
    fn detects_literal_traversal_segment() {
        let findings = scan_all("let p = base.join(\"../secret\");\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE120");
    }

    #[test]
    fn detects_untrusted_path_input() {
        let findings = scan_all("let p = base.join(user_input);\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE121");
    }

    #[test]
    fn ignores_safe_literal_join() {
        let findings = scan_all("let p = base.join(\"assets\");\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn respects_ignore_comments() {
        let findings = scan_all("// fe203-ignore FE121\nlet p = base.join(user_input);\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_traversal_in_pathbuf_from() {
        let findings = scan_all("let p = std::path::PathBuf::from(\"../secret\");\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE120");
    }
}
