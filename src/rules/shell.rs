//! Shell command construction rules: process spawning presence and
//! shell invocation with dynamically built command strings.
// fe203-ignore-file FE100, FE101

use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_rule_ignored, word_occurrences, FileContext, Rule};

const SHELL_PROGRAMS: &[&str] = &[
    "\"sh\"",
    "\"bash\"",
    "\"cmd\"",
    "\"cmd.exe\"",
    "\"powershell\"",
    "\"pwsh\"",
];
const SHELL_FLAGS: &[&str] = &["\"-c\"", "\"/c\"", "\"/C\"", "\"-Command\""];
const DYNAMIC_MARKERS: &[&str] = &["format!(", "concat!(", ".to_string()", "push_str(", " + "];

/// Detects presence of `Command::new(` / `std::process::Command::new(`.
pub struct CommandExecutionRule;

impl Rule for CommandExecutionRule {
    fn id(&self) -> &'static str {
        "FE100"
    }

    fn name(&self) -> &'static str {
        "command-execution"
    }

    fn description(&self) -> &'static str {
        "spawning an external process is worth reviewing for argument and input handling"
    }

    fn category(&self) -> Category {
        Category::Shell
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Pass arguments individually via `.arg()` and avoid invoking a shell unless required.")
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            for idx in word_occurrences(line, "Command") {
                let rest = line[idx + "Command".len()..].trim_start();
                if rest.starts_with("::new(") {
                    findings.push(self.finding(
                        ctx,
                        line_no,
                        idx + 1,
                        "`Command::new` usage found".to_string(),
                        line,
                    ));
                }
            }
        }
        findings
    }
}

/// Detects shell invocation with a dynamically constructed command string.
pub struct ShellStringInjectionRule;

impl Rule for ShellStringInjectionRule {
    fn id(&self) -> &'static str {
        "FE101"
    }

    fn name(&self) -> &'static str {
        "shell-string-injection"
    }

    fn description(&self) -> &'static str {
        "invoking a shell with a dynamically built command string is a common injection vector"
    }

    fn category(&self) -> Category {
        Category::Shell
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Avoid building shell command strings from dynamic input; pass arguments individually via `.arg()` instead of invoking a shell.")
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            let has_shell = SHELL_PROGRAMS.iter().any(|p| line.contains(p));
            let has_flag = SHELL_FLAGS.iter().any(|f| line.contains(f));
            let has_dynamic = DYNAMIC_MARKERS.iter().any(|m| line.contains(m));
            if has_shell && has_flag && has_dynamic {
                findings.push(self.finding(
                    ctx,
                    line_no,
                    line.find("Command").map(|idx| idx + 1).unwrap_or(1),
                    "shell command built from dynamic input found".to_string(),
                    line,
                ));
            }
        }
        findings
    }
}

/// All shell rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(CommandExecutionRule),
        Box::new(ShellStringInjectionRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan_all(content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(Path::new("test.rs"), content);
        rules().iter().flat_map(|r| r.scan(&ctx)).collect()
    }

    #[test]
    fn detects_command_execution_presence() {
        let findings = scan_all("std::process::Command::new(\"ls\").spawn();\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE100");
    }

    #[test]
    fn detects_dynamic_shell_string() {
        let findings =
            scan_all("Command::new(\"sh\").arg(\"-c\").arg(format!(\"echo {}\", user));\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"FE100"));
        assert!(ids.contains(&"FE101"));
    }

    #[test]
    fn ignores_static_command() {
        let findings = scan_all("Command::new(\"ls\").arg(\"-la\");\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE100"]);
    }

    #[test]
    fn respects_ignore_comments() {
        let findings = scan_all(
            "// fe203-ignore FE101\nCommand::new(\"sh\").arg(\"-c\").arg(format!(\"echo {}\", user));\n",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE100"]);
    }
}
