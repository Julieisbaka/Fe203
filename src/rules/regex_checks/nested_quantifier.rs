use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_rule_ignored, FileContext, Rule};

use super::helpers::{has_nested_quantifier, regex_call_sites};

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

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: (a+)+$\nafter: a+$")
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
            if has_nested_quantifier(pattern) {
                let snippet = lines
                    .iter()
                    .find(|(line_no, _)| *line_no == call.line_no)
                    .map(|(_, line)| *line)
                    .unwrap_or("");
                findings.push(self.finding(
                    ctx,
                    call.line_no,
                    call.column,
                    format!("suspicious nested regex quantifier in pattern `{pattern}`"),
                    snippet,
                ));
            }
        }
        findings
    }
}
