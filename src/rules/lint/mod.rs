//! General lint-style rules: clamp-like expressions, unused bindings,
//! and empty comments/docs.
// fe203-ignore-file FE060, FE061, FE062, FE065, FE066, FE075, FE076, FE077

mod clamp;
mod comments;
mod fallible;
pub(crate) mod suppressions;
mod test_reference;
mod unused;

use crate::rules::Rule;
use clamp::ClampLikePatternRule;
use comments::{EmptyCommentRule, EmptyDocCommentRule};
use suppressions::DeadSuppressionCommentRule;
use test_reference::{AssertOnlyTestsWithoutProductCallsRule, TestWithoutProductReferenceRule};
use unused::{UnusedConstantRule, UnusedVariableRule};

/// All lint-style rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = vec![
        Box::new(ClampLikePatternRule),
        Box::new(EmptyDocCommentRule),
        Box::new(EmptyCommentRule),
        Box::new(UnusedVariableRule),
        Box::new(UnusedConstantRule),
        Box::new(TestWithoutProductReferenceRule),
        Box::new(DeadSuppressionCommentRule),
        Box::new(AssertOnlyTestsWithoutProductCallsRule),
    ];
    rules.extend(fallible::rules());
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;
    use crate::rules::FileContext;
    use std::path::Path;

    fn scan_all(content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(Path::new("test.rs"), content);
        rules().iter().flat_map(|r| r.scan(&ctx)).collect()
    }

    #[test]
    fn detects_manual_clamp_chain() {
        let findings = scan_all("value.max(min).min(max);\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE060");
    }

    #[test]
    fn detects_multiline_clamp_chain() {
        let findings = scan_all("value\n    .max(min)\n    .min(max);\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE060");
    }

    #[test]
    fn detects_empty_doc_and_line_comments() {
        let findings = scan_all("///\n//!\n//\n/* */\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE061", "FE061", "FE062", "FE062"]);
    }

    #[test]
    fn ignores_non_empty_comments() {
        let findings = scan_all("/// useful\n// not empty\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_unused_variable_and_const() {
        let findings = scan_all(
            "fn f() {\n    let temp = 1;\n    const MAX_RETRY: usize = 3;\n    println!(\"{}\", temp);\n}\n",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE064"]);
    }

    #[test]
    fn ignores_string_literals_in_usage_count() {
        let findings =
            scan_all("fn f() {\n    let secret = 1;\n    let _path = \"../secret\";\n}\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE063"]);
    }

    #[test]
    fn flags_simple_unused_variable() {
        let findings = scan_all("fn f() {\n    let unused = 1;\n}\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE063");
    }

    #[test]
    fn flags_shadowed_binding_only_new_used() {
        let findings = scan_all(
            "fn f() {\n    let value = 1;\n    let value = 2;\n    println!(\"{}\", value);\n}\n",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE063"]);
    }

    #[test]
    fn keeps_binding_used_before_shadow() {
        let findings = scan_all(
            "fn f() {\n    let value = 1;\n    println!(\"{}\", value);\n    let value = 2;\n    println!(\"{}\", value);\n}\n",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.iter().all(|id| *id != "FE063"));
    }

    #[test]
    fn respects_ignore_comments() {
        let findings = scan_all("// fe203-ignore FE060\nvalue.max(min).min(max);\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_blank_doc_paragraph_break() {
        let findings = scan_all("//! Summary line.\n//!\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_isolated_empty_doc_comment() {
        let findings = scan_all("///\nfn f() {}\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE061");
    }

    #[test]
    fn detects_test_missing_product_ref() {
        let findings = scan_all("#[test]\nfn t() { assert_eq!(2, 1 + 1); }\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.iter().any(|id| *id == "FE065"));
    }

    #[test]
    fn ignores_test_with_crate_ref() {
        let findings =
            scan_all("#[test]\nfn t() { assert!(crate::parser::parse(\"x\").is_ok()); }\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_test_with_binary_ref() {
        let findings = scan_all(
            "#[tokio::test]\nasync fn t() { let _ = std::process::Command::new(\"fe203\"); }\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_non_test_files() {
        let findings = scan_all("fn helper() { assert_eq!(2, 1 + 1); }\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn respects_ignore_for_test_ref_rule() {
        let findings = scan_all(
            "// fe203-ignore-file FE065,FE075\n#[test]\nfn t() { assert_eq!(2, 1 + 1); }\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_dead_suppression_id() {
        let findings = scan_all("// fe203-ignore FE001\nfn f() {}\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE066"]);
    }

    #[test]
    fn keeps_suppression_when_rule_matches() {
        let findings = scan_all("// fe203-ignore FE001\nfn f() { todo!(); }\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_assert_only_test_missing_calls() {
        let findings = scan_all("#[test]\nfn trivial() { assert_eq!(2, 1 + 1); }\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.iter().any(|id| *id == "FE075"));
    }

    #[test]
    fn keeps_assert_test_with_product_ref() {
        let findings =
            scan_all("#[test]\nfn real() { assert!(crate::parser::parse(\"x\").is_ok()); }\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.iter().all(|id| *id != "FE075"));
    }
}
