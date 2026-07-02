//! Regex-focused rules. These are intentionally heuristic for `0.0.1`-style
//! text scanning, but they still catch common footguns.

use crate::finding::{Category, Finding, Severity};
use crate::rules::{FileContext, Rule};

const REGEX_MARKERS: &[&str] = &[
    "Regex::new(",
    "regex::Regex::new(",
    "RegexBuilder::new(",
    "regex::bytes::Regex::new(",
];

/// Detects nested quantifiers like `(a+)+` or `(.*)*` that are often a code
/// smell and can be expensive in some regex engines.
pub struct NestedQuantifierRegexRule;

impl Rule for NestedQuantifierRegexRule {
    fn id(&self) -> &'static str {
        "FE080"
    }

    fn name(&self) -> &'static str {
        "nested-regex-quantifier"
    }

    fn description(&self) -> &'static str {
        "nested quantifiers can make a regex hard to reason about and expensive in some engines"
    }

    fn category(&self) -> Category {
        Category::Regex
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Rewrite the pattern to avoid repeating a group that already contains a quantifier.")
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            for (column, pattern) in regex_literals_in_line(line) {
                if has_nested_quantifier(&pattern) {
                    findings.push(self.finding(
                        ctx,
                        line_no,
                        column,
                        format!("suspicious nested regex quantifier in pattern `{pattern}`"),
                        line,
                    ));
                }
            }
        }
        findings
    }
}

/// Detects broad or ambiguous regex constructs like repeated wildcards and
/// empty alternations.
pub struct SuspiciousRegexRule;

impl Rule for SuspiciousRegexRule {
    fn id(&self) -> &'static str {
        "FE081"
    }

    fn name(&self) -> &'static str {
        "suspicious-regex"
    }

    fn description(&self) -> &'static str {
        "overly broad wildcards and empty alternations make regexes harder to maintain"
    }

    fn category(&self) -> Category {
        Category::Regex
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Tighten the pattern by replacing broad wildcards or removing empty alternation branches.")
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            for (column, pattern) in regex_literals_in_line(line) {
                if is_suspicious_regex(&pattern) {
                    findings.push(self.finding(
                        ctx,
                        line_no,
                        column,
                        format!("suspicious regex pattern `{pattern}`"),
                        line,
                    ));
                }
            }
        }
        findings
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(NestedQuantifierRegexRule), Box::new(SuspiciousRegexRule)]
}

fn regex_literals_in_line(line: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for marker in REGEX_MARKERS {
        let mut start = 0;
        while let Some(pos) = line[start..].find(marker) {
            let idx = start + pos + marker.len();
            let rest = &line[idx..];
            let leading_ws = rest.len() - rest.trim_start().len();
            if let Some(pattern) = parse_rust_string_literal(rest.trim_start()) {
                found.push((idx + leading_ws + 1, pattern));
            }
            start = idx;
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    found.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    found
}

fn parse_rust_string_literal(input: &str) -> Option<String> {
    if input.starts_with('"') {
        parse_normal_string(input)
    } else if input.starts_with('r') {
        parse_raw_string(input)
    } else {
        None
    }
}

fn parse_normal_string(input: &str) -> Option<String> {
    let mut escaped = false;
    let mut out = String::new();
    for c in input[1..].chars() {
        if escaped {
            out.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => return Some(out),
            c => out.push(c),
        }
    }
    None
}

fn parse_raw_string(input: &str) -> Option<String> {
    let mut hashes = 0usize;
    let mut chars = input.chars();
    if chars.next()? != 'r' {
        return None;
    }
    while let Some('#') = chars.next() {
        hashes += 1;
    }
    let open = format!("r{}\"", "#".repeat(hashes));
    if !input.starts_with(&open) {
        return None;
    }
    let close = format!("\"{}", "#".repeat(hashes));
    let body = &input[open.len()..];
    let end = body.find(&close)?;
    Some(body[..end].to_string())
}

fn has_nested_quantifier(pattern: &str) -> bool {
    let mut stack = Vec::new();
    let mut escaped = false;

    for (idx, ch) in pattern.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '(' => stack.push(idx),
            ')' => {
                if let Some(start) = stack.pop() {
                    let next = pattern[idx + 1..].chars().next();
                    if matches!(next, Some('*' | '+' | '{')) {
                        let group = &pattern[start + 1..idx];
                        if group.chars().any(|c| matches!(c, '*' | '+' | '{')) {
                            return true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    false
}

fn is_suspicious_regex(pattern: &str) -> bool {
    let repeated_wildcard = pattern.contains(".*.*") || pattern.contains(".+.+");
    let broad_contains = pattern.starts_with(".*")
        && pattern.ends_with(".*")
        && (pattern.matches(".*").count() >= 2 || pattern.matches(".+").count() >= 2);
    let empty_alternation = pattern.starts_with('|')
        || pattern.ends_with('|')
        || pattern.contains("||")
        || pattern.contains("(|")
        || pattern.contains("|)");

    repeated_wildcard || broad_contains || empty_alternation
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
    fn detects_nested_quantifier_regex() {
        let findings = scan_all("let _ = regex::Regex::new(r\"(a+)+$\");\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE080");
    }

    #[test]
    fn detects_suspicious_broad_regex() {
        let findings = scan_all("let _ = Regex::new(r\".*token.*.*\");\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE081");
    }

    #[test]
    fn ignores_non_regex_strings() {
        let findings = scan_all("let pattern = r\"(a+)+$\";\n");
        assert!(findings.is_empty());
    }
}