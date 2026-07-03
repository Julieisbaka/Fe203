use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_rule_ignored, FileContext, Rule};

use super::helpers::{is_dynamic_regex_expr, regex_call_sites};

/// Detects regexes built from dynamic inputs such as `format!` or variables.
pub struct DynamicRegexRule;

impl Rule for DynamicRegexRule {
    fn id(&self) -> &'static str {
        "FE082"
    }

    fn name(&self) -> &'static str {
        "dynamic-regex"
    }

    fn description(&self) -> &'static str {
        "building regex patterns from runtime input or formatting is a common source of bugs and injection risk"
    }

    fn category(&self) -> Category {
        Category::Regex
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Prefer a fixed regex literal and validate user input separately before matching.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: Regex::new(format!(\"{}\", user))\nafter: Regex::new(r\"^[a-z]+$\")")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["regex"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines = ctx.lines().collect::<Vec<_>>();
        for call in regex_call_sites(&lines) {
            let Some((_, line)) = lines.iter().find(|(line_no, _)| *line_no == call.line_no) else {
                continue;
            };
            let line_no = call.line_no;
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            if is_dynamic_regex_expr(&call.arg) {
                findings.push(self.finding(
                    ctx,
                    line_no,
                    call.column,
                    "dynamic regex pattern construction found".to_string(),
                    line,
                ));
            }
        }
        findings
    }
}
