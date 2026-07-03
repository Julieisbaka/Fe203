use crate::finding::{Category, Finding, Severity};
use crate::rules::{FileContext, Rule};

use super::helpers::{parse_let_bindings, scan_unused_bindings};

/// Detects local variables that appear to be declared but never used.
pub struct UnusedVariableRule;

impl Rule for UnusedVariableRule {
    fn id(&self) -> &'static str {
        "FE063"
    }

    fn name(&self) -> &'static str {
        "unused-variable"
    }

    fn description(&self) -> &'static str {
        "unused variables are a sign of dead code or a missed refactor"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Remove the variable or prefix it with an underscore if it is intentionally unused.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: let value = compute();\nafter: let _value = compute();")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["let"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        scan_unused_bindings(ctx, self, parse_let_bindings, "variable")
    }
}
