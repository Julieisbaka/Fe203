//! Path-safety rules: literal traversal segments and untrusted-looking
//! path joins.
// fe203-ignore-file FE120, FE121, FE122

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
const ARCHIVE_CONTEXT_KEYWORDS: &[&str] = &["archive", "extract", "unpack", "zip", "tar"];
const ARCHIVE_ENTRY_KEYWORDS: &[&str] = &[
    "archive_entry",
    "entry_path",
    "entry_name",
    "file_name",
    "entry",
    "header",
];
const ARCHIVE_SAFE_API_KEYWORDS: &[&str] = &["enclosed_name(", "mangled_name("];

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

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["join", "push", "pathbuf"]
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

/// Detects archive extraction code that joins output paths with entry-derived
/// names without clear sanitization.
pub struct ArchiveEntryTraversalRule;

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

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["join", "push"]
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

impl Rule for ArchiveEntryTraversalRule {
    fn id(&self) -> &'static str {
        "FE122"
    }

    fn name(&self) -> &'static str {
        "archive-entry-path-traversal"
    }

    fn description(&self) -> &'static str {
        "joining archive entry names into destination paths without validation can allow traversal during extraction"
    }

    fn category(&self) -> Category {
        Category::Path
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Validate archive entry paths and reject absolute or `..` segments before joining them onto an extraction destination.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: let out = dest.join(archive_entry_path);\nafter: let out = dest.join(sanitize_archive_entry(archive_entry_path)?);")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["join", "push", "archive", "extract", "zip", "tar"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines = ctx.lines().collect::<Vec<_>>();
        for (idx, (line_no, line)) in lines.iter().enumerate() {
            if is_rule_ignored(ctx, *line_no, self.id(), self.name(), self.category()) {
                continue;
            }

            let context = extraction_context(&lines, idx);
            if !ARCHIVE_CONTEXT_KEYWORDS
                .iter()
                .any(|keyword| context.contains(keyword))
            {
                continue;
            }

            for call in JOIN_CALLS {
                for (column, arg) in call_arguments(line, call) {
                    let trimmed = arg.trim();
                    let lower = trimmed.to_ascii_lowercase();
                    if trimmed.starts_with('"')
                        || archive_arg_looks_safe(&lines, idx, line, trimmed, &lower)
                    {
                        continue;
                    }
                    if ARCHIVE_ENTRY_KEYWORDS.iter().any(|keyword| lower.contains(keyword)) {
                        findings.push(self.finding(
                            ctx,
                            *line_no,
                            column,
                            format!(
                                "archive extraction joins destination path with entry-derived input `{}`",
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
        Box::new(ArchiveEntryTraversalRule),
    ]
}

fn extraction_context(lines: &[(usize, &str)], idx: usize) -> String {
    let start = idx.saturating_sub(2);
    let end = (idx + 1).min(lines.len().saturating_sub(1));
    let mut out = String::new();
    for (_, line) in lines.iter().take(end + 1).skip(start) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&line.to_ascii_lowercase());
    }
    out
}

fn archive_arg_looks_safe(
    lines: &[(usize, &str)],
    idx: usize,
    line: &str,
    trimmed: &str,
    lower: &str,
) -> bool {
    if ARCHIVE_SAFE_API_KEYWORDS
        .iter()
        .any(|keyword| lower.contains(keyword))
    {
        return true;
    }

    if let Some(arg_name) = simple_identifier(trimmed) {
        if archive_arg_derived_from_safe_api(lines, idx, arg_name) {
            return true;
        }
    }

    joined_path_is_canonicalized(lines, idx, line)
}

fn archive_arg_derived_from_safe_api(lines: &[(usize, &str)], idx: usize, arg_name: &str) -> bool {
    let start = idx.saturating_sub(4);
    for (_, candidate) in lines.iter().take(idx).skip(start) {
        let lower = candidate.to_ascii_lowercase();
        if !candidate.contains(arg_name) {
            continue;
        }
        if ARCHIVE_SAFE_API_KEYWORDS
            .iter()
            .any(|keyword| lower.contains(keyword))
        {
            return true;
        }
    }
    false
}

fn joined_path_is_canonicalized(lines: &[(usize, &str)], idx: usize, line: &str) -> bool {
    let Some(joined_path_name) = assigned_identifier(line) else {
        return false;
    };

    let end = (idx + 4).min(lines.len().saturating_sub(1));
    let mut canonicalized_name = None;
    for (_, candidate) in lines.iter().take(end + 1).skip(idx + 1) {
        if candidate.contains(&format!("{joined_path_name}.canonicalize(")) {
            canonicalized_name = assigned_identifier(candidate);
        }
    }

    let Some(canonicalized_name) = canonicalized_name else {
        return false;
    };

    lines
        .iter()
        .take(end + 1)
        .skip(idx + 1)
        .any(|(_, candidate)| candidate.contains(&format!("{canonicalized_name}.starts_with(")))
}

fn simple_identifier(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        Some(trimmed)
    } else {
        None
    }
}

fn assigned_identifier(line: &str) -> Option<&str> {
    let mut parts = line.splitn(2, '=');
    let lhs = parts.next()?.trim();
    parts.next()?;

    let lhs = lhs.strip_prefix("let ").unwrap_or(lhs).trim();
    let lhs = lhs.strip_prefix("mut ").unwrap_or(lhs).trim();
    let lhs = lhs.split(':').next()?.trim();
    simple_identifier(lhs)
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
    fn detects_traversal_segment() {
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
    fn detects_traversal_in_pathbuf() {
        let findings = scan_all("let p = std::path::PathBuf::from(\"../secret\");\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE120");
    }

    #[test]
    fn detects_archive_entry_join() {
        let findings = scan_all(
            "fn extract_archive(archive_entry_path: &str) {\n    let out = dest.join(archive_entry_path);\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE122");
    }

    #[test]
    fn ignores_archive_entry_derived_from_enclosed_name() {
        let findings = scan_all(
            "fn extract_archive(file: &ZipFile<'_>) {\n    let entry_path = file.enclosed_name().unwrap();\n    let out = dest.join(entry_path);\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_archive_entry_guarded_by_canonicalized_path_check() {
        let findings = scan_all(
            "fn extract_archive(entry_name: &str) {\n    let out = dest.join(entry_name);\n    let canonical_out = out.canonicalize().unwrap();\n    if !canonical_out.starts_with(dest.as_path()) {\n        return;\n    }\n}\n",
        );
        assert!(findings.is_empty());
    }
}
