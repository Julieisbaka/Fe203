//! Simple hardcoded-secret rules: assignments of string literals to
//! password/api-key/secret-like identifiers and credential URLs.
// fe203-ignore-file FE040, FE041, FE042, FE043, FE044

use crate::finding::{Category, Finding, Severity};
use crate::rules::{contains_ignore_case, is_rule_ignored, FileContext, Rule};

const PROVIDER_TOKEN_PREFIXES: &[&str] = &[
    "ghp_",
    "github_pat_",
    "sk_live_",
    "sk_test_",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "ya29.",
    "glpat-",
];
const CREDENTIAL_URL_SCHEMES: &[&str] = &[
    "postgres://",
    "postgresql://",
    "mysql://",
    "mongodb://",
    "redis://",
    "amqp://",
    "http://",
    "https://",
];

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

fn assigned_string_literal(right: &str) -> Option<&str> {
    let trimmed = right.trim_start();
    let rest = trimmed.strip_prefix('"')?;
    let end = rest.find('"')?;
    if end == 0 {
        return None;
    }
    Some(&rest[..end])
}

fn looks_like_credential_url(right: &str) -> bool {
    let Some(value) = assigned_string_literal(right) else {
        return false;
    };
    if !CREDENTIAL_URL_SCHEMES
        .iter()
        .any(|scheme| value.to_ascii_lowercase().starts_with(scheme))
    {
        return false;
    }
    let Some(scheme_sep) = value.find("://") else {
        return false;
    };
    let after_scheme = &value[scheme_sep + 3..];
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let Some(at) = authority.find('@') else {
        return false;
    };
    let userinfo = &authority[..at];
    let Some(colon) = userinfo.find(':') else {
        return false;
    };
    let password = &userinfo[colon + 1..];
    colon > 0
        && !password.is_empty()
        && !matches!(
            password.to_ascii_lowercase().as_str(),
            "password" | "example"
        )
}

fn looks_like_provider_token(right: &str) -> bool {
    let Some(value) = assigned_string_literal(right) else {
        return false;
    };
    PROVIDER_TOKEN_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

pub struct CredentialUrlAssignmentRule;

impl Rule for CredentialUrlAssignmentRule {
    fn id(&self) -> &'static str {
        "FE044"
    }

    fn name(&self) -> &'static str {
        "hardcoded-credential-url"
    }

    fn description(&self) -> &'static str {
        "a string literal appears to embed credentials in a URL"
    }

    fn category(&self) -> Category {
        Category::Secrets
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Remove inline credentials from URLs and load credentials from environment or secret storage.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some(
            "before: let db = \"postgres://user:pass@db.local/app\";\nafter: let db = std::env::var(\"DATABASE_URL\")?;",
        )
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["://"]
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
            let right = &line[eq + 1..];
            if looks_like_credential_url(right) {
                findings.push(
                    self.finding(
                        ctx,
                        line_no,
                        eq + 2,
                        "possible hardcoded credential-bearing URL assigned a string literal"
                            .to_string(),
                        line,
                    ),
                );
            }
        }
        findings
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
        Some("before: let api_key = \"sk-123\";\nafter: let api_key = std::env::var(\"API_KEY\")?;")
    }

    fn should_scan(&self, ctx: &FileContext) -> bool {
        ctx.has_any_signature(self.keywords)
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
            let matched = self
                .keywords
                .iter()
                .find(|kw| contains_ignore_case(left, kw));
            if let Some(keyword) = matched {
                if self.id == "FE043"
                    && !looks_like_provider_token(right)
                    && !contains_ignore_case(left, "token")
                {
                    // Keep token findings reasonably high-signal unless the identifier
                    // explicitly says token or the literal matches a known provider prefix.
                    continue;
                }
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
        Box::new(SecretAssignmentRule {
            id: "FE043",
            name: "hardcoded-token",
            description: "a token-like identifier is assigned a string literal",
            keywords: &["token", "access_token", "auth_token", "bearer_token"],
        }),
        Box::new(CredentialUrlAssignmentRule),
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
            "const API_KEY: &str = \"sk_live_12345\";\n",
            "let client_secret = \"shhh\";\n",
            "let access_token = \"ghp_1234567890abcdef\";\n",
            "let database_url = \"postgres://user:pass@db.local/app\";\n",
        ));
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE040", "FE041", "FE042", "FE043", "FE044"]);
    }

    #[test]
    fn ignores_empty_and_non_literal() {
        let findings = scan_all(concat!(
            "let password = \"\";\n",
            "let password = read_password();\n",
            "if password == \"hunter2\" {}\n",
        ));
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_unrelated_assignments() {
        let findings =
            scan_all("let name = \"fe203\";\nlet homepage = \"https://example.com/account\";\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn respects_ignore_comments() {
        let findings = scan_all("// fe203-ignore FE040\nlet password = \"hunter2\";\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_credential_url_no_password() {
        let findings = scan_all(concat!(
            "let db = \"postgres://user:pass@db.local/app\";\n",
            "let no_pass = \"postgres://user@db.local/app\";\n",
            "let placeholder = \"postgres://user:password@db.local/app\";\n",
        ));
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE044"]);
    }
}
