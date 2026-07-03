use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_rule_ignored, FileContext, Rule};

use super::helpers::{
    is_anchored, looks_like_regex, looks_like_validation_context_near, nearby_regex_patterns,
    string_literals_in_line,
};

/// Detects validation-style regexes that are not anchored with `^` and `$`.
pub struct UnanchoredValidationRegexRule;

impl Rule for UnanchoredValidationRegexRule {
    fn id(&self) -> &'static str {
        "FE083"
    }

    fn name(&self) -> &'static str {
        "unanchored-validation-regex"
    }

    fn description(&self) -> &'static str {
        "validation regexes that lack anchors can accept partial matches unexpectedly"
    }

    fn category(&self) -> Category {
        Category::Regex
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Anchor the pattern with `^...$` if the regex is meant to validate the entire input.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: re.is_match(r\"[a-z]+\")\nafter: re.is_match(r\"^[a-z]+$\")")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["is_match", "captures"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines = ctx.lines().collect::<Vec<_>>();
        for (idx, (line_no, line)) in lines.iter().enumerate() {
            if is_rule_ignored(ctx, *line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            if !line.contains("is_match(") && !line.contains("captures(") {
                continue;
            }
            let validation_context = looks_like_validation_context_near(&lines, idx);
            for (column, pattern) in string_literals_in_line(line) {
                if looks_like_regex(&pattern) && !is_anchored(&pattern) && validation_context {
                    findings.push(self.finding(
                        ctx,
                        *line_no,
                        column,
                        format!("unanchored validation regex `{pattern}`"),
                        line,
                    ));
                }
            }

            if !findings
                .iter()
                .any(|finding| finding.rule_id == self.id() && finding.line == *line_no)
            {
                for (pattern_line_no, column, pattern) in nearby_regex_patterns(&lines, idx) {
                    if !is_anchored(&pattern) && validation_context {
                        findings.push(self.finding(
                            ctx,
                            pattern_line_no,
                            column,
                            format!("unanchored validation regex `{pattern}`"),
                            line,
                        ));
                        break;
                    }
                }
            }
        }
        findings
    }
}
