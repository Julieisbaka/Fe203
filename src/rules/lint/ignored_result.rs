use crate::finding::{Category, Finding, Severity};
use crate::rules::syntax::collect_method_chains;
use crate::rules::{is_rule_ignored, FileContext, Rule};

const PRODUCT_PREFIXES: &[&str] = &["crate::", "super::", "self::", "fe203::"];

/// Detects bare statements that call product code and silently drop the
/// returned value.
pub struct IgnoredProductResultRule;

impl Rule for IgnoredProductResultRule {
    fn id(&self) -> &'static str {
        "FE079"
    }

    fn name(&self) -> &'static str {
        "ignored-product-call-result"
    }

    fn description(&self) -> &'static str {
        "product-code calls whose results are silently dropped often hide unchecked failures"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Use the returned value, assert on it, or bind it explicitly with `let _ =` to show the drop is intentional.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: crate::parser::parse(\"x\");\nafter: assert!(crate::parser::parse(\"x\").is_ok());")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["crate", "super", "fe203"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let bytes = ctx.content.as_bytes();
        for chain in collect_method_chains(ctx.content) {
            if !PRODUCT_PREFIXES
                .iter()
                .any(|prefix| chain.root.starts_with(prefix))
            {
                continue;
            }
            if !is_bare_statement(bytes, chain.start, chain.end) {
                continue;
            }
            if is_rule_ignored(ctx, chain.line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            let snippet = ctx
                .content
                .lines()
                .nth(chain.line_no.saturating_sub(1))
                .unwrap_or("");
            findings.push(self.finding(
                ctx,
                chain.line_no,
                chain.column,
                format!("result of product call `{}` is silently dropped", chain.root),
                snippet,
            ));
        }
        findings
    }
}

/// True when the chain occupies a whole statement: preceded by a statement
/// boundary (`{`, `}`, `;`, or file start) and terminated directly by `;`.
fn is_bare_statement(bytes: &[u8], start: usize, end: usize) -> bool {
    let mut before = start;
    while before > 0 && bytes[before - 1].is_ascii_whitespace() {
        before -= 1;
    }
    if before != 0 && !matches!(bytes[before - 1], b'{' | b'}' | b';') {
        return false;
    }

    let mut after = end;
    while after < bytes.len() && bytes[after].is_ascii_whitespace() {
        after += 1;
    }
    bytes.get(after) == Some(&b';')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan_all(content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(Path::new("src/lib.rs"), content);
        IgnoredProductResultRule.scan(&ctx)
    }

    #[test]
    fn detects_dropped_product_call() {
        let findings = scan_all("fn run() {\n    crate::parser::parse(\"x\");\n}\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE079");
    }

    #[test]
    fn detects_dropped_product_chain() {
        let findings = scan_all("fn run() {\n    crate::store::open(path).validate();\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_bound_and_returned_results() {
        let findings = scan_all(
            "fn run() -> bool {\n    let ok = crate::parser::parse(\"x\");\n    let _ = crate::parser::parse(\"y\");\n    return crate::parser::check(ok);\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_calls_used_inside_expressions() {
        let findings = scan_all(
            "fn run() {\n    assert!(crate::parser::parse(\"x\").is_ok());\n    if crate::parser::valid(\"y\") { return; }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn respects_ignore_comments() {
        let findings =
            scan_all("fn run() {\n    // fe203-ignore FE079\n    crate::parser::parse(\"x\");\n}\n");
        assert!(findings.is_empty());
    }
}
