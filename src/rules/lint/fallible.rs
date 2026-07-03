use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_comment_line, is_rule_ignored, FileContext, Rule};
use crate::rules::syntax::{collect_invocations, extract_annotated_functions, InvocationKind};

const TEST_ATTR_MARKERS: &[&str] = &[
    "#[test]",
    "#[tokio::test]",
    "#[actix_rt::test]",
    "#[actix_web::test]",
    "#[async_std::test]",
];

/// Detects `unwrap`/`expect`-style calls outside test code.
pub struct UnwrapExpectRule;

impl Rule for UnwrapExpectRule {
    fn id(&self) -> &'static str {
        "FE076"
    }

    fn name(&self) -> &'static str {
        "unwrap-expect-outside-tests"
    }

    fn description(&self) -> &'static str {
        "unwrap/expect calls outside tests can turn recoverable failures into crashes"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Handle the error explicitly or propagate it with `?` instead of using unwrap/expect in non-test code.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: let cfg = read_config().unwrap();\nafter: let cfg = read_config()?;")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["unwrap", "expect"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        if in_tests_directory(ctx) {
            return Vec::new();
        }

        let test_ranges = test_function_ranges(ctx.content);
        let mut findings = Vec::new();
        for invocation in collect_invocations(ctx.content) {
            if invocation.kind != InvocationKind::Call
                || line_in_ranges(invocation.line_no, &test_ranges)
            {
                continue;
            }
            let method = invocation.path.rsplit('.').next().unwrap_or(invocation.path);
            if !matches!(method, "unwrap" | "expect" | "unwrap_err" | "expect_err") {
                continue;
            }
            let line = ctx
                .content
                .lines()
                .nth(invocation.line_no.saturating_sub(1))
                .unwrap_or("");
            if is_rule_ignored(ctx, invocation.line_no, self.id(), self.name(), self.category())
                || is_comment_line(line)
            {
                continue;
            }
            findings.push(self.finding(
                ctx,
                invocation.line_no,
                invocation.column,
                format!("non-test code uses `{method}`"),
                line,
            ));
        }
        findings
    }
}

/// Detects closures that erase underlying error details like `map_err(|_| ...)`.
pub struct ErrorErasureRule;

impl Rule for ErrorErasureRule {
    fn id(&self) -> &'static str {
        "FE077"
    }

    fn name(&self) -> &'static str {
        "error-erasure"
    }

    fn description(&self) -> &'static str {
        "mapping all errors to `_` erases useful debugging context"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Preserve the original error context or include it in the mapped error value.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: result.map_err(|_| MyError::BadInput)\nafter: result.map_err(|err| MyError::BadInputWithSource(err.to_string()))")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["map_err", "or_else"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        if in_tests_directory(ctx) {
            return Vec::new();
        }

        let test_ranges = test_function_ranges(ctx.content);
        let mut findings = Vec::new();
        for invocation in collect_invocations(ctx.content) {
            if invocation.kind != InvocationKind::Call
                || line_in_ranges(invocation.line_no, &test_ranges)
            {
                continue;
            }
            let method = invocation.path.rsplit('.').next().unwrap_or(invocation.path);
            if !matches!(method, "map_err" | "or_else") {
                continue;
            }
            let Some(args) = invocation.args else {
                continue;
            };
            if !args.trim_start().starts_with("|_|") {
                continue;
            }
            let line = ctx
                .content
                .lines()
                .nth(invocation.line_no.saturating_sub(1))
                .unwrap_or("");
            if is_rule_ignored(ctx, invocation.line_no, self.id(), self.name(), self.category())
                || is_comment_line(line)
            {
                continue;
            }
            findings.push(self.finding(
                ctx,
                invocation.line_no,
                invocation.column,
                "error mapping erases the original error value".to_string(),
                line,
            ));
        }
        findings
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(UnwrapExpectRule), Box::new(ErrorErasureRule)]
}

fn in_tests_directory(ctx: &FileContext) -> bool {
    let path = ctx.path.to_string_lossy().replace('\\', "/");
    path.contains("/tests/") || path.starts_with("tests/")
}

fn line_in_ranges(line_no: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| line_no >= *start && line_no <= *end)
}

fn test_function_ranges(content: &str) -> Vec<(usize, usize)> {
    extract_annotated_functions(content, TEST_ATTR_MARKERS)
        .into_iter()
        .map(|function| (function.line_no, function.end_line))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan_all(content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(Path::new("src/lib.rs"), content);
        rules().iter().flat_map(|rule| rule.scan(&ctx)).collect()
    }

    #[test]
    fn detects_unwrap_outside_tests() {
        let findings = scan_all("fn load() { let cfg = read_config().unwrap(); }\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE076");
    }

    #[test]
    fn ignores_unwrap_inside_test_function() {
        let findings = scan_all("#[test]\nfn it_works() { let cfg = read_config().unwrap(); }\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_error_erasure() {
        let findings = scan_all("fn load() { let _ = result.map_err(|_| \"bad\"); }\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE077");
    }

    #[test]
    fn detects_multiline_unwrap_outside_tests() {
        let findings = scan_all("fn load() {\n    let cfg = read_config()\n        .unwrap();\n}\n");
        assert!(findings.iter().any(|finding| finding.rule_id == "FE076"));
    }

    #[test]
    fn ignores_unwrap_in_strings_and_comments() {
        let findings = scan_all(
            "fn load() {\n    let _ = \".unwrap()\";\n    // .expect(\"x\")\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_multiline_error_erasure() {
        let findings = scan_all(
            "fn load() {\n    let _ = result\n        .map_err(\n            |_| \"bad\"\n        );\n}\n",
        );
        assert!(findings.iter().any(|finding| finding.rule_id == "FE077"));
    }
}
