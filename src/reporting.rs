//! Output rendering: human-readable console report and JSON.
// fe203-ignore-file FE001

use crate::finding::Finding;

/// Human-readable report, grouped by file.
pub fn render_human(findings: &[Finding], files_scanned: usize, rules_enabled: usize) -> String {
    let mut out = String::new();
    let mut current_file: Option<&std::path::Path> = None;

    for finding in findings {
        if current_file != Some(finding.file.as_path()) {
            if current_file.is_some() {
                out.push('\n');
            }
            out.push_str(&format!("{}\n", finding.file.display()));
            current_file = Some(finding.file.as_path());
        }
        out.push_str(&format!(
            "  {}:{}  {:<8} {}  {} [{}]\n",
            finding.line,
            finding.column,
            finding.severity.name(),
            finding.rule_id,
            finding.message,
            finding.rule_name,
        ));
        out.push_str(&format!("      | {}\n", finding.snippet));
        if let Some(suggestion) = &finding.suggestion {
            out.push_str(&format!("      = help: {}\n", suggestion));
        }
    }

    if !findings.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!(
        "{} finding(s) in {} file(s) scanned ({} rule(s) enabled)\n",
        findings.len(),
        files_scanned,
        rules_enabled
    ));
    out
}

/// JSON array of findings.
pub fn render_json(findings: &[Finding]) -> String {
    let mut out = String::from("[");
    for (i, finding) in findings.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"rule_id\":{},\"rule_name\":{},\"category\":{},\"severity\":{},\"file\":{},\"line\":{},\"column\":{},\"message\":{},\"snippet\":{},\"suggestion\":{}}}",
            json_string(finding.rule_id),
            json_string(finding.rule_name),
            json_string(finding.category.name()),
            json_string(finding.severity.name()),
            json_string(&finding.file.display().to_string()),
            finding.line,
            finding.column,
            json_string(&finding.message),
            json_string(&finding.snippet),
            json_optional_string(finding.suggestion.as_deref()),
        ));
    }
    out.push(']');
    out
}

fn json_optional_string(s: Option<&str>) -> String {
    match s {
        Some(s) => json_string(s),
        None => "null".to_string(),
    }
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Category, Severity};
    use std::path::PathBuf;

    fn sample() -> Finding {
        Finding {
            rule_id: "FE001",
            rule_name: "todo-macro",
            category: Category::Debug,
            severity: Severity::Warning,
            file: PathBuf::from("src/main.rs"),
            line: 2,
            column: 5,
            message: "`todo!` macro found".to_string(),
            snippet: "todo!();".to_string(),
            suggestion: Some(
                "Implement the code path or remove the placeholder macro.".to_string(),
            ),
        }
    }

    #[test]
    fn human_report_includes_location_and_summary() {
        let report = render_human(&[sample()], 3, 9);
        assert!(report.contains("src/main.rs"));
        assert!(report.contains("2:5"));
        assert!(report.contains("FE001"));
        assert!(report.contains("help: Implement the code path or remove the placeholder macro."));
        assert!(report.contains("1 finding(s) in 3 file(s) scanned (9 rule(s) enabled)"));
    }

    #[test]
    fn json_output_escapes_and_structures() {
        let json = render_json(&[sample()]);
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        assert!(json.contains("\"rule_id\":\"FE001\""));
        assert!(json.contains("\"severity\":\"warning\""));
        assert!(json.contains("\"suggestion\":"));
        assert!(json.contains("\\u0060todo!\\u0060") || json.contains("`todo!`"));
    }

    #[test]
    fn empty_findings_render_cleanly() {
        assert_eq!(render_json(&[]), "[]");
        let report = render_human(&[], 5, 9);
        assert!(report.contains("0 finding(s)"));
    }
}
