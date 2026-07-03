use crate::finding::{Category, Finding, Severity};
use crate::rules::{FileContext, Rule};

use super::helpers::{parse_const_bindings, scan_unused_bindings};

/// Detects constants that appear to be declared but never used.
pub struct UnusedConstantRule;

impl Rule for UnusedConstantRule {
    fn id(&self) -> &'static str {
        "FE064"
    }

    fn name(&self) -> &'static str {
        "unused-constant"
    }

    fn description(&self) -> &'static str {
        "unused constants often indicate dead code or stale configuration"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Remove the constant or use it at every call site that needs it.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: const MAX_RETRY: usize = 3;\nafter: let retries = MAX_RETRY;")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["const"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        scan_unused_bindings(ctx, self, parse_const_bindings, "constant")
    }
}
