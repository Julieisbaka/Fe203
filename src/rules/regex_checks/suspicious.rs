use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_rule_ignored, FileContext, Rule};

use super::helpers::{is_suspicious_regex, regex_call_sites};

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

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: .*token.*.*\nafter: ^[A-Za-z0-9_]*token[A-Za-z0-9_]*$")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["regex"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines = ctx.lines().collect::<Vec<_>>();
        for call in regex_call_sites(&lines) {
            if is_rule_ignored(ctx, call.line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            let Some(pattern) = &call.pattern else {
                continue;
            };
            if is_suspicious_regex(pattern) {
                let snippet = lines
                    .iter()
                    .find(|(line_no, _)| *line_no == call.line_no)
                    .map(|(_, line)| *line)
                    .unwrap_or("");
                findings.push(self.finding(
                    ctx,
                    call.line_no,
                    call.column,
                    format!("suspicious regex pattern `{pattern}`"),
                    snippet,
                ));
            }
        }
        findings
    }
}
