//! Unsafe-usage rules: unsafe syntax and APIs with strong safety obligations.
// fe203-ignore-file FE020, FE022, FE023, FE024

use crate::finding::{Category, Finding, Severity};
use crate::rules::syntax::{collect_invocations, InvocationKind};
use crate::rules::{is_comment_line, is_rule_ignored, word_occurrences, FileContext, Rule};

/// Whether the `unsafe` keyword at `idx` is followed by `fn`.
fn is_unsafe_fn(line: &str, idx: usize) -> bool {
    let rest = line[idx + "unsafe".len()..].trim_start();
    rest == "fn" || rest.starts_with("fn ") || rest.starts_with("fn(")
}

/// Detects `unsafe` usage that is not an `unsafe fn` declaration
/// (blocks, impls, traits).
pub struct UnsafeUsageRule;

impl Rule for UnsafeUsageRule {
    fn id(&self) -> &'static str {
        "FE020"
    }
    fn name(&self) -> &'static str {
        "unsafe-usage"
    }
    fn description(&self) -> &'static str {
        "`unsafe` code bypasses Rust's safety guarantees and deserves review"
    }
    fn category(&self) -> Category {
        Category::Unsafe
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some("Isolate unsafe code behind a safe abstraction and document the safety invariants.")
    }
    fn suggestion_example(&self) -> Option<&'static str> {
        Some(
            "before: unsafe { ptr.read() }\nafter: // SAFETY: ptr is valid and aligned\nlet value = unsafe { ptr.read() };",
        )
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["unsafe"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            if is_comment_line(line) {
                continue;
            }
            for idx in word_occurrences(line, "unsafe") {
                if !is_unsafe_fn(line, idx) {
                    findings.push(self.finding(
                        ctx,
                        line_no,
                        idx + 1,
                        "`unsafe` usage found".to_string(),
                        line,
                    ));
                }
            }
        }
        findings
    }
}

/// Detects `unsafe fn` declarations.
pub struct UnsafeFnRule;

impl Rule for UnsafeFnRule {
    fn id(&self) -> &'static str {
        "FE021"
    }
    fn name(&self) -> &'static str {
        "unsafe-fn"
    }
    fn description(&self) -> &'static str {
        "`unsafe fn` pushes safety obligations onto every caller"
    }
    fn category(&self) -> Category {
        Category::Unsafe
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some("Prefer a safe function if possible, or document the caller obligations in a Safety section.")
    }
    fn suggestion_example(&self) -> Option<&'static str> {
        Some(
            "before: pub unsafe fn from_raw(p: *const u8) -> T\nafter: /// # Safety\n/// `p` must point to ...\npub unsafe fn from_raw(p: *const u8) -> T",
        )
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["unsafe", "fn"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            if is_comment_line(line) {
                continue;
            }
            for idx in word_occurrences(line, "unsafe") {
                if is_unsafe_fn(line, idx) {
                    findings.push(self.finding(
                        ctx,
                        line_no,
                        idx + 1,
                        "`unsafe fn` declaration found".to_string(),
                        line,
                    ));
                }
            }
        }
        findings
    }
}

struct RiskyApiRule {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    api_names: &'static [&'static str],
    suggestion: &'static str,
}

impl Rule for RiskyApiRule {
    fn id(&self) -> &'static str {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn description(&self) -> &'static str {
        self.description
    }

    fn category(&self) -> Category {
        Category::Unsafe
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some(self.suggestion)
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        self.api_names
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let lines: Vec<_> = ctx.lines().collect();
        collect_invocations(ctx.content)
            .into_iter()
            .filter_map(|invocation| {
                let api = invocation.path.rsplit("::").next()?;
                if invocation.kind != InvocationKind::Call || !self.api_names.contains(&api) {
                    return None;
                }
                if is_rule_ignored(ctx, invocation.line_no, self.id(), self.name(), self.category())
                {
                    return None;
                }
                let line = lines
                    .iter()
                    .find(|(line_no, _)| *line_no == invocation.line_no)
                    .map(|(_, line)| *line)?;
                if is_comment_line(line) {
                    return None;
                }
                Some(self.finding(
                    ctx,
                    invocation.line_no,
                    invocation.column,
                    format!("`{}` has significant safety obligations", invocation.path),
                    line,
                ))
            })
            .collect()
    }
}

/// All unsafe-usage rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(UnsafeUsageRule),
        Box::new(UnsafeFnRule),
        Box::new(RiskyApiRule {
            id: "FE022",
            name: "transmute",
            description: "`transmute` reinterprets a value's bits and can violate type invariants",
            api_names: &["transmute", "transmute_copy"],
            suggestion: "Prefer a checked conversion or a safe standard-library conversion.",
        }),
        Box::new(RiskyApiRule {
            id: "FE023",
            name: "mem-forget",
            description: "`mem::forget` skips destructors and can leak resources",
            api_names: &["forget"],
            suggestion: "Avoid suppressing a destructor unless the resource ownership is deliberately transferred.",
        }),
        Box::new(RiskyApiRule {
            id: "FE024",
            name: "mem-zeroed",
            description: "`mem::zeroed` can create invalid values for many Rust types",
            api_names: &["zeroed"],
            suggestion: "Use `Default`, `MaybeUninit`, or a type-specific constructor that preserves invariants.",
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan_all(content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(Path::new("test.rs"), content);
        rules().iter().flat_map(|r| r.scan(&ctx)).collect()
    }

    #[test]
    fn detects_unsafe_block() {
        let findings = scan_all("fn f() {\n    unsafe { do_thing() }\n}\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE020");
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn detects_unsafe_fn_separately() {
        // fe203-ignore FE021
        let findings = scan_all("pub unsafe fn danger() {}\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE021");
    }

    #[test]
    fn ignores_comments_and_idents() {
        // fe203-ignore FE021
        let findings = scan_all("// unsafe fn in a comment\nlet not_unsafe_here = 1;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn respects_ignore_comments() {
        let findings = scan_all("// fe203-ignore FE020\nunsafe { do_thing() }\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_risky_memory_apis_and_ignores_comments() {
        let findings = scan_all(concat!(
            "let value = std::mem::transmute::<u32, f32>(bits);\n",
            "std::mem::forget(resource);\n",
            "let value = std::mem::zeroed::<T>();\n",
            "// std::mem::transmute(bits)\n",
        ));
        let ids: Vec<&str> = findings.iter().map(|finding| finding.rule_id).collect();
        assert_eq!(ids, ["FE022", "FE023", "FE024"]);
    }
}
