use super::*;
use std::path::Path;

fn scan_all(content: &str) -> Vec<Finding> {
    let ctx = FileContext::new(Path::new("test.rs"), content);
    rules().iter().flat_map(|rule| rule.scan(&ctx)).collect()
}

#[test]
fn detects_traversal_segment() {
    let findings = scan_all("let p = base.join(\"../secret\");\n");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "FE120");
}

#[test]
fn detects_untrusted_path_input() {
    let findings = scan_all("let p = base.join(user_input);\n");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "FE121");
}

#[test]
fn ignores_safe_literal_join() {
    let findings = scan_all("let p = base.join(\"assets\");\n");
    assert!(findings.is_empty());
}

#[test]
fn respects_ignore_comments() {
    let findings = scan_all("// fe203-ignore FE121\nlet p = base.join(user_input);\n");
    assert!(findings.is_empty());
}

#[test]
fn detects_traversal_in_pathbuf() {
    let findings = scan_all("let p = std::path::PathBuf::from(\"../secret\");\n");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "FE120");
}

#[test]
fn detects_archive_entry_join() {
    let findings = scan_all(
        "fn extract_archive(archive_entry_path: &str) {\n    let out = dest.join(archive_entry_path);\n}\n",
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "FE122");
}

#[test]
fn ignores_archive_entry_derived_from_enclosed_name() {
    let findings = scan_all(
        "fn extract_archive(file: &ZipFile<'_>) {\n    let entry_path = file.enclosed_name().unwrap();\n    let out = dest.join(entry_path);\n}\n",
    );
    assert!(findings.is_empty());
}

#[test]
fn ignores_archive_entry_guarded_by_canonicalized_path_check() {
    let findings = scan_all(
        "fn extract_archive(entry_name: &str) {\n    let out = dest.join(entry_name);\n    let canonical_out = out.canonicalize().unwrap();\n    if !canonical_out.starts_with(dest.as_path()) {\n        return;\n    }\n}\n",
    );
    assert!(findings.is_empty());
}

#[test]
fn detects_absolute_joins_and_lossy_conversions() {
    let findings = scan_all(concat!(
        "let path = base.join(\"/etc/passwd\");\n",
        "let text = path.to_string_lossy();\n",
        "let bytes = String::from_utf8_lossy(input);\n",
        "let relative = base.join(\"child\");\n",
    ));
    let ids: Vec<&str> = findings.iter().map(|finding| finding.rule_id).collect();
    assert_eq!(ids, ["FE123", "FE124", "FE124"]);
}
