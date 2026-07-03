use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_comment_line, is_rule_ignored, FileContext, Rule};

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
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category())
                || is_comment_line(line)
                || line_in_ranges(line_no, &test_ranges)
            {
                continue;
            }

            let markers = [".unwrap()", ".expect(", ".unwrap_err()", ".expect_err("];
            for marker in markers {
                if let Some(column) = line.find(marker) {
                    findings.push(self.finding(
                        ctx,
                        line_no,
                        column + 1,
                        format!(
                            "non-test code uses `{}`",
                            marker.trim_start_matches('.').trim_end_matches('(')
                        ),
                        line,
                    ));
                    break;
                }
            }
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
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category())
                || is_comment_line(line)
                || line_in_ranges(line_no, &test_ranges)
            {
                continue;
            }

            let markers = ["map_err(|_|", "or_else(|_|"];
            for marker in markers {
                if let Some(column) = line.find(marker) {
                    findings.push(self.finding(
                        ctx,
                        line_no,
                        column + 1,
                        "error mapping erases the original error value".to_string(),
                        line,
                    ));
                    break;
                }
            }
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
    let mut out = Vec::new();
    let mut pending_attr = false;
    let mut line_start = 0usize;

    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if TEST_ATTR_MARKERS
            .iter()
            .any(|marker| trimmed.contains(marker))
        {
            pending_attr = true;
        } else if pending_attr && (trimmed.starts_with("fn ") || trimmed.contains(" fn ")) {
            if let Some(open_rel) = content[line_start..].find('{') {
                let open = line_start + open_rel;
                if let Some(close) = find_matching_brace(content, open) {
                    let end_line = content[..close]
                        .bytes()
                        .filter(|byte| *byte == b'\n')
                        .count()
                        + 1;
                    out.push((line_no, end_line));
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
            b'{' => {
                depth += 1;
                idx += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                idx += 1;
                if depth == 0 {
                    return Some(idx - 1);
                }
            }
            b'"' => idx = skip_string_literal(bytes, idx + 1),
            b'\'' => idx = skip_char_literal(bytes, idx + 1),
            b'/' if idx + 1 < bytes.len() && bytes[idx + 1] == b'/' => {
                idx += 2;
                while idx < bytes.len() && bytes[idx] != b'\n' {
                    idx += 1;
                }
            }
            b'/' if idx + 1 < bytes.len() && bytes[idx + 1] == b'*' => {
                idx += 2;
                while idx + 1 < bytes.len() {
                    if bytes[idx] == b'*' && bytes[idx + 1] == b'/' {
                        idx += 2;
                        break;
                    }
                    idx += 1;
                }
            }
            _ => idx += 1,
        }
    }
    None
}

fn skip_string_literal(bytes: &[u8], mut idx: usize) -> usize {
    let mut escaped = false;
    while idx < bytes.len() {
        if escaped {
            escaped = false;
            idx += 1;
            continue;
        }
        match bytes[idx] {
            b'\\' => {
                escaped = true;
                idx += 1;
            }
            b'"' => return idx + 1,
            _ => idx += 1,
        }
    }
    idx
}

fn skip_char_literal(bytes: &[u8], mut idx: usize) -> usize {
    let mut escaped = false;
    while idx < bytes.len() {
        if escaped {
            escaped = false;
            idx += 1;
            continue;
        }
        match bytes[idx] {
            b'\\' => {
                escaped = true;
                idx += 1;
            }
            b'\'' => return idx + 1,
            _ => idx += 1,
        }
    }
    idx
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
}
