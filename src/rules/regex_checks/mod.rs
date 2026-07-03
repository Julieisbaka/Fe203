//! Regex-focused rules. These are intentionally heuristic.
//! text scanning, but they still catch common footguns.
// fe203-ignore-file FE080, FE081, FE082, FE083

mod dynamic;
mod helpers;
mod nested_quantifier;
mod suspicious;
mod unanchored;

use dynamic::DynamicRegexRule;
use nested_quantifier::NestedQuantifierRegexRule;
use suspicious::SuspiciousRegexRule;
use unanchored::UnanchoredValidationRegexRule;

pub fn rules() -> Vec<Box<dyn crate::rules::Rule>> {
    vec![
        Box::new(NestedQuantifierRegexRule),
        Box::new(SuspiciousRegexRule),
        Box::new(DynamicRegexRule),
        Box::new(UnanchoredValidationRegexRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::helpers::scan_all_for_tests;
    use super::*;
    use crate::finding::Finding;

    fn scan_all(content: &str) -> Vec<Finding> {
        scan_all_for_tests(content, &rules())
    }

    #[test]
    fn detects_nested_quantifier() {
        let findings = scan_all("let _ = regex::Regex::new(r\"(a+)+$\");\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE080");
    }

    #[test]
    fn detects_broad_regex() {
        let findings = scan_all("let _ = Regex::new(r\".*token.*.*\");\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE081");
    }

    #[test]
    fn ignores_non_regex_strings() {
        let findings = scan_all("let pattern = r\"(a+)+$\";\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_dynamic_regex_build() {
        let findings = scan_all("let re = Regex::new(format!(\"{}\", user));\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE082");
    }

    #[test]
    fn detects_unanchored_validation() {
        let findings = scan_all("let ok = re.is_match(r\"[a-z]+\");\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE083");
    }

    #[test]
    fn detects_unanchored_capture() {
        let findings = scan_all("let valid_name = re.captures(\"[a-z]+\");\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE083");
    }

    #[test]
    fn ignores_search_context_is_match() {
        let findings = scan_all("let search_result = re.is_match(\"[a-z]+\");\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_builder_dynamic_regex() {
        let findings = scan_all("let re = RegexBuilder::new(format!(\"{}\", pattern));\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE082");
    }

    #[test]
    fn detects_empty_alternation() {
        let findings = scan_all("let _ = Regex::new(r\"foo||bar\");\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE081");
    }

    #[test]
    fn respects_ignore_comments() {
        let findings = scan_all("// fe203-ignore FE080\nlet _ = Regex::new(r\"(a+)+$\");\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_unrelated_find_calls() {
        let findings = scan_all("let todo = rules.iter().find(|r| r.id() == \"FE001\");\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_anchored_validation() {
        let findings = scan_all("let ok = re.is_match(r\"^[a-z]+$\");\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_compile_time_concat_regex() {
        let findings = scan_all("let re = Regex::new(concat!(r\"^foo\", r\"bar$\"));\n");
        assert!(findings.iter().all(|finding| finding.rule_id != "FE082"));
    }

    #[test]
    fn detects_identifier_based_dynamic_regex() {
        let findings = scan_all("let pattern = user_supplied();\nlet re = Regex::new(pattern);\n");
        assert!(findings.iter().any(|finding| finding.rule_id == "FE082"));
    }

    #[test]
    fn detects_multiline_dynamic_regex_builder() {
        let findings = scan_all("let re = Regex::new(\n    format!(\"{}\", user)\n);\n");
        assert!(findings.iter().any(|finding| finding.rule_id == "FE082"));
    }

    #[test]
    fn detects_validation_regex_from_nearby_builder() {
        let findings = scan_all(
            "let valid_name = Regex::new(\"[a-z]+\").unwrap();\nlet ok = valid_name.is_match(input);\n",
        );
        assert!(findings.iter().any(|finding| finding.rule_id == "FE083"));
    }

    #[test]
    fn ignores_search_regex_from_nearby_builder() {
        let findings = scan_all(
            "let search_re = Regex::new(\"[a-z]+\").unwrap();\nlet ok = search_re.is_match(input);\n",
        );
        assert!(findings.iter().all(|finding| finding.rule_id != "FE083"));
    }

    #[test]
    fn ignores_quantifier_inside_character_class() {
        let findings = scan_all("let _ = Regex::new(r\"([+*])+\");\n");
        assert!(findings.iter().all(|finding| finding.rule_id != "FE080"));
    }
}
