use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_rule_ignored, FileContext, Rule};
use crate::rules::syntax::{collect_invocations, extract_annotated_functions, InvocationKind};

/// Detects test-bearing files that do not appear to reference product code.
pub struct TestWithoutProductReferenceRule;

impl Rule for TestWithoutProductReferenceRule {
    fn id(&self) -> &'static str {
        "FE065"
    }

    fn name(&self) -> &'static str {
        "test-without-product-reference"
    }

    fn description(&self) -> &'static str {
        "tests that never reference product code can become disconnected from real behavior"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Reference crate/module code in test bodies so assertions validate real behavior.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: #[test] fn t(){ assert_eq!(2,1+1); }\nafter: #[test] fn t(){ assert!(crate::parser::parse(\"x\").is_ok()); }")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["test"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let test_functions = extract_test_functions(ctx.content);
        let Some(line_no) = test_functions.first().map(|test_fn| test_fn.line_no) else {
            return Vec::new();
        };
        if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
            return Vec::new();
        }
        if test_functions.iter().any(|test_fn| has_product_reference(test_fn.body)) {
            return Vec::new();
        }
        let snippet = ctx
            .content
            .lines()
            .nth(line_no.saturating_sub(1))
            .unwrap_or("");
        vec![self.finding(
            ctx,
            line_no,
            1,
            "test code found without any product-code reference".to_string(),
            snippet,
        )]
    }
}

/// Detects individual test functions that only perform trivial assertions and
/// do not call into product code.
pub struct AssertOnlyTestsWithoutProductCallsRule;

/// Detects tests that call product code but never assert on behavior.
pub struct TestWithoutAssertionsRule;

impl Rule for AssertOnlyTestsWithoutProductCallsRule {
    fn id(&self) -> &'static str {
        "FE075"
    }

    fn name(&self) -> &'static str {
        "assert-only-tests-without-product-calls"
    }

    fn description(&self) -> &'static str {
        "assert-only tests that never call product code can pass without validating behavior"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Call crate/module code inside each test and assert on real outputs.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: #[test] fn t() { assert_eq!(2, 1 + 1); }\nafter: #[test] fn t() { assert!(crate::parser::parse(\"x\").is_ok()); }")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["test", "assert"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for test_fn in extract_test_functions(ctx.content) {
            if is_rule_ignored(
                ctx,
                test_fn.line_no,
                self.id(),
                self.name(),
                self.category(),
            ) {
                continue;
            }
            if has_product_reference(test_fn.body) {
                continue;
            }
            if !contains_assert_macro(test_fn.body) {
                continue;
            }
            if !assert_only_expression_style(test_fn.body) {
                continue;
            }
            findings.push(self.finding(
                ctx,
                test_fn.line_no,
                1,
                "test function uses assertions but does not call product code".to_string(),
                test_fn.header,
            ));
        }
        findings
    }
}

impl Rule for TestWithoutAssertionsRule {
    fn id(&self) -> &'static str {
        "FE078"
    }

    fn name(&self) -> &'static str {
        "test-without-assertions"
    }

    fn description(&self) -> &'static str {
        "tests that call product code but never assert on outputs or effects can silently pass"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Assert on a concrete output, error, or side effect so the test validates behavior.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: #[test] fn t() { crate::parser::parse(\"x\"); }\nafter: #[test] fn t() { assert!(crate::parser::parse(\"x\").is_ok()); }")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["test"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for test_fn in extract_test_functions(ctx.content) {
            if is_rule_ignored(
                ctx,
                test_fn.line_no,
                self.id(),
                self.name(),
                self.category(),
            ) {
                continue;
            }
            if !has_direct_product_call(test_fn.body) || contains_assert_macro(test_fn.body) {
                continue;
            }
            findings.push(self.finding(
                ctx,
                test_fn.line_no,
                1,
                "test function calls product code without any assertion".to_string(),
                test_fn.header,
            ));
        }
        findings
    }
}

struct TestFunction<'a> {
    line_no: usize,
    header: &'a str,
    body: &'a str,
}

fn extract_test_functions(content: &str) -> Vec<TestFunction<'_>> {
    extract_annotated_functions(content, TEST_ATTR_MARKERS)
        .into_iter()
        .map(|function| TestFunction {
            line_no: function.line_no,
            header: function.header,
            body: function.body,
        })
        .collect()
}

fn contains_assert_macro(body: &str) -> bool {
    collect_invocations(body).into_iter().any(|invocation| {
        invocation.kind == InvocationKind::Macro
            && ASSERT_MACROS.iter().any(|name| *name == invocation.path)
    })
}

fn assert_only_expression_style(body: &str) -> bool {
    collect_invocations(body).into_iter().all(|invocation| {
        invocation.kind == InvocationKind::Macro
            && ASSERT_MACROS.iter().any(|allowed| *allowed == invocation.path)
    })
}

fn has_product_reference(content: &str) -> bool {
    collect_invocations(content).into_iter().any(|invocation| {
        invocation.path.starts_with("crate::")
            || invocation.path.starts_with("super::")
            || invocation.path.starts_with("self::")
            || invocation.path.starts_with("fe203::")
            || (invocation.kind == InvocationKind::Macro
                && invocation.path == "env"
                && invocation
                    .args
                    .is_some_and(|args| args.contains("\"CARGO_BIN_EXE_fe203\"")))
            || (invocation.kind == InvocationKind::Call
                && (invocation.path == "Command::new"
                    || invocation.path == "std::process::Command::new")
                && invocation
                    .args
                    .is_some_and(|args| args.trim_start().starts_with("\"fe203\"")))
    })
}

fn has_direct_product_call(content: &str) -> bool {
    collect_invocations(content).into_iter().any(|invocation| {
        invocation.kind == InvocationKind::Call
            && (invocation.path.starts_with("crate::")
                || invocation.path.starts_with("super::")
                || invocation.path.starts_with("self::")
                || invocation.path.starts_with("fe203::"))
    })
}

const TEST_ATTR_MARKERS: &[&str] = &[
    "#[test]",
    "#[tokio::test]",
    "#[actix_rt::test]",
    "#[actix_web::test]",
    "#[async_std::test]",
];

const ASSERT_MACROS: &[&str] = &[
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan_with_rules(content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(Path::new("test.rs"), content);
        vec![
            Box::new(TestWithoutProductReferenceRule) as Box<dyn Rule>,
            Box::new(AssertOnlyTestsWithoutProductCallsRule),
            Box::new(TestWithoutAssertionsRule),
        ]
        .iter()
        .flat_map(|rule| rule.scan(&ctx))
        .collect()
    }

    #[test]
    fn ignores_product_reference_in_comments_and_strings() {
        let findings = scan_with_rules(
            "#[test]\nfn t() {\n    let _ = \"crate::fake()\";\n    // crate::fake()\n    assert_eq!(2, 1 + 1);\n}\n",
        );
        let ids: Vec<&str> = findings.iter().map(|finding| finding.rule_id).collect();
        assert!(ids.iter().any(|id| *id == "FE065"));
        assert!(ids.iter().any(|id| *id == "FE075"));
    }

    #[test]
    fn ignores_test_with_braces_inside_strings() {
        let findings = scan_with_rules(
            "#[test]\nfn t() {\n    let _ = \"{ not code }\";\n    assert!(crate::parser::parse(\"x\").is_ok());\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn keeps_command_new_fe203_as_product_reference() {
        let findings = scan_with_rules(
            "#[test]\nfn t() {\n    let _ = std::process::Command::new(\"fe203\");\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_product_call_without_assertion() {
        let findings = scan_with_rules(
            "#[test]\nfn t() {\n    crate::parser::parse(\"x\");\n}\n",
        );
        assert!(findings.iter().any(|finding| finding.rule_id == "FE078"));
    }
}
