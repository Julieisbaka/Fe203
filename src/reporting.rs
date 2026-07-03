//! Output rendering: human-readable console report and JSON.
// fe203-ignore-file FE001

use std::collections::HashSet;

use crate::config::Config;
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
        if let Some(example) = &finding.suggestion_example {
            out.push_str("      = example:\n");
            for line in example.lines() {
                out.push_str(&format!("          {}\n", line));
            }
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
            "{{\"rule_id\":{},\"rule_name\":{},\"category\":{},\"severity\":{},\"file\":{},\"line\":{},\"column\":{},\"message\":{},\"snippet\":{},\"suggestion\":{},\"suggestion_example\":{}}}",
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
            json_optional_string(finding.suggestion_example.as_deref()),
        ));
    }
    out.push(']');
    out
}

pub fn render_json_pretty(findings: &[Finding]) -> String {
    pretty_json(&render_json(findings))
}

pub fn render_sarif(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{");
    out.push_str("\"tool\":{\"driver\":{\"name\":\"fe203\",\"version\":");
    out.push_str(&json_string(env!("CARGO_PKG_VERSION")));
    out.push_str("}},\"results\":[");

    for (i, finding) in findings.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let level = match finding.severity.name() {
            "critical" | "high" => "error",
            "warning" => "warning",
            _ => "note",
        };
        out.push_str("{\"ruleId\":");
        out.push_str(&json_string(finding.rule_id));
        out.push_str(",\"level\":");
        out.push_str(&json_string(level));
        out.push_str(",\"message\":{\"text\":");
        out.push_str(&json_string(&finding.message));
        out.push_str("},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":");
        out.push_str(&json_string(&finding.file.display().to_string().replace('\\', "/")));
        out.push_str("},\"region\":{\"startLine\":");
        out.push_str(&finding.line.to_string());
        out.push_str(",\"startColumn\":");
        out.push_str(&finding.column.to_string());
        out.push_str("}}}]");
        if let Some(help) = &finding.suggestion {
            out.push_str(",\"help\":");
            out.push_str(&json_string(help));
        }
        out.push('}');
    }

    out.push_str("]}]}");
    out
}

pub fn render_sarif_pretty(findings: &[Finding]) -> String {
    pretty_json(&render_sarif(findings))
}

pub fn apply_severity_overrides(findings: &mut [Finding], config: &Config) {
    for finding in findings {
        if let Some(override_severity) = config.severity.get(finding.rule_id) {
            finding.severity = *override_severity;
        }
    }
}

pub fn baseline_lines(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .map(finding_signature)
        .collect::<Vec<_>>()
}

pub fn apply_baseline(findings: &[Finding], baseline_text: &str) -> Vec<Finding> {
    let known: HashSet<&str> = baseline_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    findings
        .iter()
        .filter(|finding| !known.contains(finding_signature(finding).as_str()))
        .cloned()
        .collect()
}

fn finding_signature(finding: &Finding) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        finding.rule_id,
        finding.file.display().to_string().replace('\\', "/"),
        finding.line,
        finding.column,
        finding.message
    )
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

fn pretty_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + input.len() / 2);
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for c in input.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }

        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '{' | '[' => {
                out.push(c);
                depth += 1;
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
                out.push(c);
            }
            ',' => {
                out.push(c);
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
            }
            ':' => {
                out.push(':');
                out.push(' ');
            }
            c if c.is_whitespace() => {}
            _ => out.push(c),
        }
    }

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
            suggestion_example: Some("before: todo!()\nafter: return Err(err);".to_string()),
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
        assert!(json.contains("\"suggestion_example\":"));
        assert!(json.contains("\\u0060todo!\\u0060") || json.contains("`todo!`"));
    }

    #[test]
    fn pretty_json_output_contains_newlines() {
        let pretty = render_json_pretty(&[sample()]);
        assert!(pretty.contains('\n'));
        assert!(pretty.contains("\"rule_id\": \"FE001\""));
    }

    #[test]
    fn sarif_output_contains_schema_and_rule_id() {
        let sarif = render_sarif(&[sample()]);
        assert!(sarif.contains("\"version\":\"2.1.0\""));
        assert!(sarif.contains("\"ruleId\":\"FE001\""));
    }

    #[test]
    fn pretty_sarif_output_contains_newlines() {
        let sarif = render_sarif_pretty(&[sample()]);
        assert!(sarif.contains('\n'));
        assert!(sarif.contains("\"ruleId\": \"FE001\""));
    }

    #[test]
    fn baseline_filters_existing_finding() {
        let finding = sample();
        let line = baseline_lines(std::slice::from_ref(&finding)).join("\n");
        let filtered = apply_baseline(&[finding], &line);
        assert!(filtered.is_empty());
    }

    #[test]
    fn empty_findings_render_cleanly() {
        assert_eq!(render_json(&[]), "[]");
        let report = render_human(&[], 5, 9);
        assert!(report.contains("0 finding(s)"));
    }
}
