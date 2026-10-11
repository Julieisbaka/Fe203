use super::*;
use std::path::Path;

fn scan_all(content: &str) -> Vec<Finding> {
    let ctx = FileContext::new(Path::new("test.rs"), content);
    rules().iter().flat_map(|r| r.scan(&ctx)).collect()
}

#[test]
fn detects_each_secret_kind() {
    let findings = scan_all(concat!(
        "let password = \"hunter2\";\n",
        "const API_KEY: &str = \"sk_live_12345\";\n",
        "let client_secret = \"shhh\";\n",
        "let access_token = \"ghp_1234567890abcdef\";\n",
        "let database_url = \"postgres://user:pass@db.local/app\";\n",
    ));
    let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, ["FE040", "FE041", "FE042", "FE043", "FE044"]);
}

#[test]
fn ignores_empty_and_non_literal() {
    let findings = scan_all(concat!(
        "let password = \"\";\n",
        "let password = read_password();\n",
        "if password == \"hunter2\" {}\n",
    ));
    assert!(findings.is_empty());
}

#[test]
fn ignores_unrelated_assignments() {
    let findings =
        scan_all("let name = \"fe203\";\nlet homepage = \"https://example.com/account\";\n");
    assert!(findings.is_empty());
}

#[test]
fn respects_ignore_comments() {
    let findings = scan_all("// fe203-ignore FE040\nlet password = \"hunter2\";\n");
    assert!(findings.is_empty());
}

#[test]
fn detects_credential_url_no_password() {
    let findings = scan_all(concat!(
        "let db = \"postgres://user:pass@db.local/app\";\n",
        "let no_pass = \"postgres://user@db.local/app\";\n",
        "let placeholder = \"postgres://user:password@db.local/app\";\n",
    ));
    let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, ["FE044"]);
}

#[test]
fn detects_weak_hash_tls_bypass_and_private_key_marker() {
    let findings = scan_all(concat!(
        "let digest = Md5::new();\n",
        "let client = builder.danger_accept_invalid_certs(true);\n",
        "let key = \"-----BEGIN PRIVATE KEY-----\";\n",
        "// -----BEGIN PRIVATE KEY----- is only an example\n",
    ));
    let ids: Vec<&str> = findings.iter().map(|finding| finding.rule_id).collect();
    assert_eq!(ids, ["FE045", "FE046", "FE047"]);
}

#[test]
fn ignores_tls_validation_when_set_to_false_and_respects_suppression() {
    let findings = scan_all(concat!(
        "builder.danger_accept_invalid_certs(false);\n",
        "// fe203-ignore FE046\n",
        "builder.danger_accept_invalid_hostnames(true);\n",
    ));
    assert!(findings.is_empty());
}
