mod constant;
mod helpers;
mod variable;

pub(super) use constant::UnusedConstantRule;
pub(super) use variable::UnusedVariableRule;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;
    use crate::rules::{FileContext, Rule};
    use std::path::Path;

    fn scan_all(content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(Path::new("test.rs"), content);
        vec![
            Box::new(UnusedVariableRule) as Box<dyn Rule>,
            Box::new(UnusedConstantRule),
        ]
        .iter()
        .flat_map(|rule| rule.scan(&ctx))
        .collect()
    }

    #[test]
    fn detects_unused_destructured_binding() {
        let findings = scan_all("let (left, right) = (1, 2);\nprintln!(\"{}\", left);\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE063"]);
        assert!(findings[0].message.contains("right"));
    }

    #[test]
    fn ignores_used_shadow_chain() {
        let findings = scan_all(
            "let value = 1;\nlet value = value + 1;\nlet value = value + 1;\nprintln!(\"{}\", value);\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_unused_multiline_destructured_binding() {
        let findings =
            scan_all("let (\n    left,\n    right,\n) = pair();\nprintln!(\"{}\", left);\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("right"));
    }

    #[test]
    fn keeps_outer_use_after_inner_shadow_block() {
        let findings = scan_all(
            "let value = 1;\n{\n    let value = 2;\n    println!(\"{}\", value);\n}\nprintln!(\"{}\", value);\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_unused_nested_struct_pattern_binding() {
        let findings =
            scan_all("let Foo { left: Some(inner), right } = value;\nprintln!(\"{}\", right);\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("inner"));
    }

    #[test]
    fn ignores_if_let_and_while_let_patterns() {
        let findings = scan_all(
            "if let Some(value) = maybe { println!(\"{}\", value); }\nwhile let Some(item) = next() { println!(\"{}\", item); }\n",
        );
        assert!(findings.iter().all(|f| f.rule_id != "FE063"));
    }

    #[test]
    fn detects_unused_nested_tuple_struct_and_enum_pattern_binding() {
        let findings = scan_all(
            "let Some(Foo(inner, used)) = value;\nprintln!(\"{}\", used);\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("inner"));
    }

    #[test]
    fn keeps_used_binding_with_raw_string_initializer() {
        let findings = scan_all(
            "let value = r#\"; not the end { }\"#;\nprintln!(\"{}\", value);\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn keeps_used_binding_with_nested_block_comment_in_initializer() {
        let findings = scan_all(
            "let value = 1 /* outer /* inner */ still outer */;\nprintln!(\"{}\", value);\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn keeps_used_binding_with_macro_heavy_initializer() {
        let findings = scan_all(
            "let value = format!(\"{}\", { let inner = 1; inner + 1 });\nprintln!(\"{}\", value);\n",
        );
        assert!(findings.is_empty());
    }
}