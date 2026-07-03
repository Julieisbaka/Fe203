use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_rule_ignored, FileContext, Rule};

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
        let Some(line_no) = first_test_attr_line(ctx.content) else {
            return Vec::new();
        };
        if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
            return Vec::new();
        }
        if has_product_reference(ctx.content) {
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

struct TestFunction<'a> {
    line_no: usize,
    header: &'a str,
    body: &'a str,
}

fn extract_test_functions(content: &str) -> Vec<TestFunction<'_>> {
    let mut out = Vec::new();
    let mut pending_attr = false;
    let mut line_start = 0usize;

    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if TEST_ATTR_MARKERS.iter().any(|m| trimmed.contains(m)) {
            pending_attr = true;
        } else if pending_attr && (trimmed.starts_with("fn ") || trimmed.contains(" fn ")) {
            if let Some(open_rel) = content[line_start..].find('{') {
                let open = line_start + open_rel;
                if let Some(close) = find_matching_brace(content, open) {
                    let body_start = open.saturating_add(1);
                    let body = &content[body_start..close];
                    out.push(TestFunction {
                        line_no,
                        header: line,
                        body,
                    });
                    pending_attr = false;
                }
            }
        } else if !trimmed.starts_with("#[") && !trimmed.is_empty() {
            pending_attr = false;
        }

        line_start += line.len() + 1;
    }

    out
}

fn find_matching_brace(content: &str, open: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    let mut depth = 0usize;
    let mut idx = open;
    while idx < bytes.len() {
        match bytes[idx] {
            b'{' => depth += 1,
            b'}' => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
        idx += 1;
    }
    None
}

fn contains_assert_macro(body: &str) -> bool {
    ASSERT_MACROS
        .iter()
        .any(|name| body.contains(&format!("{name}!")))
}

fn assert_only_expression_style(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if is_ident_start(bytes[idx]) {
            let start = idx;
            idx += 1;
            while idx < bytes.len() && is_ident_continue(bytes[idx]) {
                idx += 1;
            }
            let ident = &body[start..idx];

            let mut cursor = idx;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }

            if cursor < bytes.len() && bytes[cursor] == b'!' {
                if !ASSERT_MACROS.iter().any(|allowed| allowed == &ident) {
                    return false;
                }
            } else if cursor < bytes.len() && bytes[cursor] == b'(' {
                return false;
            }
        } else {
            idx += 1;
        }
    }
    true
}

fn first_test_attr_line(content: &str) -> Option<usize> {
    const TEST_ATTR_MARKERS: &[&str] = &[
        "#[test]",
        "#[tokio::test]",
        "#[actix_rt::test]",
        "#[actix_web::test]",
        "#[async_std::test]",
    ];
    content.lines().enumerate().find_map(|(idx, line)| {
        let trimmed = line.trim();
        if TEST_ATTR_MARKERS.iter().any(|m| trimmed.contains(m)) {
            Some(idx + 1)
        } else {
            None
        }
    })
}

fn has_product_reference(content: &str) -> bool {
    const PRODUCT_REF_MARKERS: &[&str] = &[
        "crate::",
        "super::",
        "self::",
        "fe203::",
        "env!(\"CARGO_BIN_EXE_fe203\")",
        "Command::new(\"fe203\")",
        "std::process::Command::new(\"fe203\")",
    ];
    PRODUCT_REF_MARKERS
        .iter()
        .any(|marker| content.contains(marker))
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

fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_ident_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}
