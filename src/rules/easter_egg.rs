//! An opt-in joke rule, intentionally omitted from the generated rule index.

use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_comment_line, is_rule_ignored, FileContext, Rule};

const MARKER: &str = "fe203-easter-egg";

struct EasterEggRule;

impl Rule for EasterEggRule {
    fn id(&self) -> &'static str {
        "FE203"
    }

    fn name(&self) -> &'static str {
        "easter-egg"
    }

    fn description(&self) -> &'static str {
        "A surprise for anyone who knows where to look"
    }

    fn category(&self) -> Category {
        Category::Debug
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn is_hidden(&self) -> bool {
        true
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &[MARKER]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        ctx.lines()
            .filter_map(|(line_no, line)| {
                if !is_comment_line(line)
                    || is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category())
                {
                    return None;
                }
                let column = line.find(MARKER)? + 1;
                Some(
                    self.finding(
                        ctx,
                        line_no,
                        column,
                        "Rule FE203 has inspected your code and found it suspiciously lintable."
                            .to_string(),
                        line,
                    ),
                )
            })
            .collect()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(EasterEggRule)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{all_rules, render_rule_index};
    use std::path::Path;

    fn scan(content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(Path::new("test.rs"), content);
        rules().iter().flat_map(|rule| rule.scan(&ctx)).collect()
    }

    #[test]
    fn reports_joke_for_opt_in_comment_marker() {
        let findings = scan("// fe203-easter-egg\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE203");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn ignores_marker_outside_comment_and_honors_suppression() {
        assert!(scan("let marker = \"fe203-easter-egg\";\n").is_empty());
        assert!(scan("// fe203-ignore FE203\n// fe203-easter-egg\n").is_empty());
    }

    #[test]
    fn is_registered_but_omitted_from_rule_index() {
        let registry = all_rules();
        assert!(registry.iter().any(|rule| rule.id() == "FE203"));
        assert!(!render_rule_index(&registry).contains("FE203"));
    }
}
