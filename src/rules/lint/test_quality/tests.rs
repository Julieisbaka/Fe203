use super::*;
use std::path::Path;

fn scan(content: &str) -> Vec<Finding> {
    let ctx = FileContext::new(Path::new("src/lib.rs"), content);
    rules().iter().flat_map(|rule| rule.scan(&ctx)).collect()
}

#[test]
fn detects_result_defaults_discarded_calls_and_vague_expect_messages() {
    let findings = scan(concat!(
        "fn read() {\n",
        "    let contents = std::fs::read_to_string(path).unwrap_or_default();\n",
        "    file.write_all(bytes);\n",
        "    result.expect(\"ok\");\n",
        "}\n",
    ));
    let ids: Vec<&str> = findings.iter().map(|finding| finding.rule_id).collect();
    assert_eq!(ids, ["FE068", "FE069", "FE070"]);
}

#[test]
fn detects_ignored_empty_and_tautological_tests_and_sleep() {
    let findings = scan(concat!(
        "#[test]\n#[ignore]\nfn ignored() { assert!(true); }\n",
        "#[test]\nfn empty() {}\n",
        "#[test]\nfn tautology() { assert_eq!(value, value); }\n",
        "#[tokio::test]\nasync fn waits() { tokio::time::sleep(duration).await; }\n",
    ));
    let ids: Vec<&str> = findings.iter().map(|finding| finding.rule_id).collect();
    assert_eq!(ids, ["FE071", "FE072", "FE073", "FE073", "FE074"]);
}
