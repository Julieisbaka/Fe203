//! Simple hardcoded-secret rules: assignments of string literals to
//! password/api-key/secret-like identifiers.
// fe203-ignore-file FE040, FE041, FE042

use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_rule_ignored, FileContext, Rule};

/// Detects `<identifier containing keyword> = "non-empty literal"`.
pub struct SecretAssignmentRule {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    /// Lowercased keywords; a match requires the identifier left of `=`
    /// to contain one of these.
    keywords: &'static [&'static str],
}

/// Finds the byte index of the first assignment `=` in `line`, skipping
/// comparison/arrow/compound operators like `==`, `!=`, `<=`, `>=`, `=>`, `+=`.
fn assignment_eq_index(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'=' {
            continue;
        }
        let prev = if i > 0 { bytes[i - 1] } else { b' ' };
        let next = if i + 1 < bytes.len() {
            bytes[i + 1]
        } else {
            b' '
        };
        if matches!(
            prev,
            b'=' | b'!' | b'<' | b'>' | b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^'
        ) {
            continue;
        }
        if matches!(next, b'=' | b'>') {
            continue;
        }
        return Some(i);
    }
    None
}

/// True if `right` (the text after `=`) starts with a non-empty string literal.
fn assigns_nonempty_string(right: &str) -> bool {
    let trimmed = right.trim_start();
    let Some(rest) = trimmed.strip_prefix('"') else {
        return false;
    };
    match rest.find('"') {
        Some(end) => end > 0,
        None => false,
    }
}

impl Rule for SecretAssignmentRule {
    fn id(&self) -> &'static str {
        self.id
    }
    fn name(&self) -> &'static str {
        self.name
    }
    fn description(&self) -> &'static str {
        self.description
    }
    fn category(&self) -> Category {
        Category::Secrets
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some("Move the secret into environment-based configuration or a dedicated secret store.")
    }
    fn suggestion_example(&self) -> Option<&'static str> {
        Some(
            "before: let api_key = \"sk-123\";\nafter: let api_key = std::env::var(\"API_KEY\")?;",
        )
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            let Some(eq) = assignment_eq_index(line) else {
                continue;
            };
            let (left, right) = (&line[..eq], &line[eq + 1..]);
            if !assigns_nonempty_string(right) {
                continue;
            }
            let left_lower = left.to_lowercase();
            let matched = self.keywords.iter().find(|kw| left_lower.contains(**kw));
            if let Some(keyword) = matched {
                findings.push(self.finding(
                    ctx,
                    line_no,
                    eq + 2,
                    format!("possible hardcoded {} assigned a string literal", keyword),
                    line,
                ));
            }
        }
        findings
    }
}

/// All secret-detection rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SecretAssignmentRule {
            id: "FE040",
            name: "hardcoded-password",
            description: "a password-like identifier is assigned a string literal",
            keywords: &["password", "passwd"],
        }),
        Box::new(SecretAssignmentRule {
            id: "FE041",
            name: "hardcoded-api-key",
            description: "an API-key-like identifier is assigned a string literal",
            keywords: &["api_key", "apikey"],
        }),
        Box::new(SecretAssignmentRule {
            id: "FE042",
            name: "hardcoded-secret",
            description: "a secret-like identifier is assigned a string literal",
            keywords: &["secret"],
        }),
    ]
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
    fn detects_each_secret_kind() {
        let findings = scan_all(concat!(
            "let password = \"hunter2\";\n",
            "const API_KEY: &str = \"sk-12345\";\n",
            "let client_secret = \"shhh\";\n",
        ));
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE040", "FE041", "FE042"]);
    }

    #[test]
    fn ignores_empty_and_non_literal_values() {
        let findings = scan_all(concat!(
            "let password = \"\";\n",
            "let password = read_password();\n",
            "if password == \"hunter2\" {}\n",
        ));
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_unrelated_assignments() {
        let findings = scan_all("let name = \"fe203\";\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn respects_ignore_comments() {
        let findings = scan_all("// fe203-ignore FE040\nlet password = \"hunter2\";\n");
        assert!(findings.is_empty());
    }
}
