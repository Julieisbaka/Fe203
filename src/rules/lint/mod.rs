//! General lint-style rules: clamp-like expressions, unused bindings,
//! and empty comments/docs.
// fe203-ignore-file FE060, FE061, FE062, FE065, FE066, FE075

mod clamp;
mod comments;
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
    vec![
        Box::new(ClampLikePatternRule),
        Box::new(EmptyDocCommentRule),
        Box::new(EmptyCommentRule),
        Box::new(UnusedVariableRule),
        Box::new(UnusedConstantRule),
        Box::new(TestWithoutProductReferenceRule),
        Box::new(DeadSuppressionCommentRule),
        Box::new(AssertOnlyTestsWithoutProductCallsRule),
    ]
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
    fn detects_empty_doc_comments_and_empty_comments() {
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
    fn detects_unused_variable_and_constant() {
        let findings = scan_all(
            "fn f() {\n    let temp = 1;\n    const MAX_RETRY: usize = 3;\n    println!(\"{}\", temp);\n}\n",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE064"]);
    }

    #[test]
    fn ignores_string_literals_when_counting_variable_usage() {
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
    fn flags_shadowed_binding_when_only_new_binding_is_used() {
        let findings = scan_all(
            "fn f() {\n    let value = 1;\n    let value = 2;\n    println!(\"{}\", value);\n}\n",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE063"]);
    }

    #[test]
    fn does_not_flag_binding_used_before_shadowing() {
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
    fn ignores_blank_doc_line_used_as_paragraph_break() {
        let findings = scan_all("//! Summary line.\n//!\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_truly_isolated_empty_doc_comment() {
        let findings = scan_all("///\nfn f() {}\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE061");
    }

    #[test]
    fn detects_test_without_product_reference() {
        let findings = scan_all("#[test]\nfn t() { assert_eq!(2, 1 + 1); }\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.iter().any(|id| *id == "FE065"));
    }

    #[test]
    fn ignores_test_with_crate_reference() {
        let findings =
            scan_all("#[test]\nfn t() { assert!(crate::parser::parse(\"x\").is_ok()); }\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_test_with_binary_invocation_reference() {
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
    fn respects_ignore_for_test_reference_rule() {
        let findings = scan_all(
            "// fe203-ignore-file FE065,FE075\n#[test]\nfn t() { assert_eq!(2, 1 + 1); }\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_dead_suppression_rule_id() {
        let findings = scan_all("// fe203-ignore FE001\nfn f() {}\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE066"]);
    }

    #[test]
    fn does_not_flag_suppression_when_rule_would_match() {
        let findings = scan_all("// fe203-ignore FE001\nfn f() { todo!(); }\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_assert_only_test_without_product_calls() {
        let findings = scan_all("#[test]\nfn trivial() { assert_eq!(2, 1 + 1); }\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.iter().any(|id| *id == "FE075"));
    }

    #[test]
    fn does_not_flag_assert_test_with_product_reference() {
        let findings = scan_all(
            "#[test]\nfn real() { assert!(crate::parser::parse(\"x\").is_ok()); }\n",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.iter().all(|id| *id != "FE075"));
    }
}
