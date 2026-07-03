//! Shell command construction rules: process spawning presence and
//! shell invocation with dynamically built command strings.
// fe203-ignore-file FE100, FE101

use crate::finding::{Category, Finding, Severity};
use crate::rules::syntax::collect_method_chains;
use crate::rules::{is_rule_ignored, word_occurrences, FileContext, Rule};

const SHELL_PROGRAMS: &[&str] = &["sh", "bash", "cmd", "cmd.exe", "powershell", "pwsh"];
const SHELL_FLAGS: &[&str] = &["-c", "/c", "/C", "-Command"];
const DYNAMIC_MARKERS: &[&str] = &["format!(", "concat!(", ".to_string()", "push_str(", " + "];
const ENV_VAR_MARKERS: &[&str] = &["std::env::var(", "env::var(", "std::env::args(", "env::args("];

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
    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: Command::new(\"sh\").arg(\"-c\").arg(cmd)\nafter: Command::new(\"ls\").arg(\"-la\")")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["command"]
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
    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: .arg(format!(\"echo {}\", user))\nafter: .arg(\"echo\").arg(user)")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["command", "sh", "bash", "powershell", "cmd"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let env_bound_vars = env_bound_variable_names(ctx.content);
        for chain in collect_method_chains(ctx.content) {
            if !chain.root.ends_with("Command::new") {
                continue;
            }
            if is_rule_ignored(ctx, chain.line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            let invokes_shell = chain
                .root_args
                .is_some_and(|args| is_string_literal_of(args, SHELL_PROGRAMS));
            if !invokes_shell {
                continue;
            }
            let mut saw_shell_flag = false;
            let mut risky_arg = None;
            for call in &chain.calls {
                if call.name != "arg" && call.name != "args" {
                    continue;
                }
                if is_string_literal_of(call.args, SHELL_FLAGS) {
                    saw_shell_flag = true;
                    continue;
                }
                let dynamic = DYNAMIC_MARKERS.iter().any(|m| call.args.contains(m));
                let env_input = ENV_VAR_MARKERS.iter().any(|m| call.args.contains(m))
                    || env_bound_vars
                        .iter()
                        .any(|name| statement_contains_identifier(call.args, name));
                if saw_shell_flag && (dynamic || env_input) {
                    risky_arg = Some(call);
                    break;
                }
            }
            if let Some(call) = risky_arg {
                let snippet = ctx
                    .content
                    .lines()
                    .nth(chain.line_no.saturating_sub(1))
                    .unwrap_or("");
                findings.push(self.finding(
                    ctx,
                    call.line_no,
                    call.column,
                    "shell command built from dynamic input found".to_string(),
                    snippet,
                ));
            }
        }
        findings
    }
}

/// True if `args` is exactly one string literal whose value is in `allowed`.
fn is_string_literal_of(args: &str, allowed: &[&str]) -> bool {
    let trimmed = args.trim();
    let Some(inner) = trimmed
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    else {
        return false;
    };
    !inner.contains('"') && allowed.contains(&inner)
}

/// All shell rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(CommandExecutionRule),
        Box::new(ShellStringInjectionRule),
    ]
}

fn env_bound_variable_names(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in content.lines() {
        if !(line.contains("std::env::var(")
            || line.contains("env::var(")
            || line.contains("std::env::args(")
            || line.contains("env::args("))
        {
            continue;
        }

        if let Some((name, _)) = parse_simple_let_name(line) {
            if !out.iter().any(|existing| existing == &name) {
                out.push(name);
            }
        }
    }
    out
}

fn parse_simple_let_name(line: &str) -> Option<(String, usize)> {
    let trimmed = line.trim_start();
    let mut offset = line.len() - trimmed.len();
    let mut rest = trimmed.strip_prefix("let ")?;
    offset += 4;
    let ws = rest.len() - rest.trim_start().len();
    rest = rest.trim_start();
    offset += ws;
    if let Some(after_mut) = rest.strip_prefix("mut ") {
        rest = after_mut.trim_start();
        offset += 4;
    }

    let mut name = String::new();
    for ch in rest.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            name.push(ch);
        } else {
            break;
        }
    }
    if name.is_empty() {
        None
    } else {
        Some((name, offset))
    }
}

fn line_contains_identifier(line: &str, name: &str) -> bool {
    !word_occurrences(line, name).is_empty()
}

fn statement_contains_identifier(statement: &str, name: &str) -> bool {
    line_contains_identifier(statement, name)
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
    fn detects_command_execution() {
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
    fn detects_env_var_shell_string() {
        let findings = scan_all(
            "let home = std::env::var(\"HOME\").unwrap();\nCommand::new(\"sh\").arg(\"-c\").arg(home);\n",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"FE101"));
    }

    #[test]
    fn detects_multiline_dynamic_shell_string() {
        let findings = scan_all(
            "Command::new(\"sh\")\n    .arg(\"-c\")\n    .arg(format!(\"echo {}\", user));\n",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"FE101"));
    }

    #[test]
    fn detects_multiline_env_shell_string() {
        let findings = scan_all(
            "let home = std::env::var(\"HOME\").unwrap();\nCommand::new(\"sh\")\n    .arg(\"-c\")\n    .arg(home);\n",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
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
