use crate::finding::{Category, Finding, Severity};
use crate::rules::syntax::collect_method_chains;
use crate::rules::{is_comment_line, is_rule_ignored, word_occurrences, FileContext, Rule};

const SOURCE_MARKERS: &[&str] = &[
    "env::var(",
    "env::args(",
    "args_os(",
    "read_line(",
    "stdin(",
    "request.",
    "query.",
    "params.",
];
const SOURCE_NAME_PARTS: &[&str] = &["user", "input", "argument", "request", "query"];

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(UncontrolledCommandRule)]
}

struct UncontrolledCommandRule;

impl Rule for UncontrolledCommandRule {
    fn id(&self) -> &'static str {
        "FE102"
    }

    fn name(&self) -> &'static str {
        "uncontrolled-command-line"
    }

    fn description(&self) -> &'static str {
        "untrusted data passed to an external command can alter its behavior"
    }

    fn category(&self) -> Category {
        Category::Shell
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Validate the executable and arguments against an allowlist before starting the process.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["Command::new", ".arg(", ".args("]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let tainted = controlled_data_names(ctx.content);
        let lines: Vec<_> = ctx.lines().collect();
        let mut findings = Vec::new();

        for chain in collect_method_chains(ctx.content) {
            let is_command = chain.root.ends_with("Command::new");
            if !is_command {
                continue;
            }

            if let Some(args) = chain.root_args {
                if is_controlled(args, &tainted) {
                    add_finding(
                        self,
                        ctx,
                        &lines,
                        &mut findings,
                        chain.line_no,
                        chain.column,
                    );
                }
            }
            for call in chain.calls {
                if matches!(call.name, "arg" | "args") && is_controlled(call.args, &tainted) {
                    add_finding(self, ctx, &lines, &mut findings, call.line_no, call.column);
                }
            }
        }
        findings
    }
}

fn add_finding(
    rule: &UncontrolledCommandRule,
    ctx: &FileContext,
    lines: &[(usize, &str)],
    findings: &mut Vec<Finding>,
    line_no: usize,
    column: usize,
) {
    if is_rule_ignored(ctx, line_no, rule.id(), rule.name(), rule.category()) {
        return;
    }
    if let Some((_, line)) = lines.iter().find(|(number, _)| *number == line_no) {
        findings.push(
            rule.finding(
                ctx,
                line_no,
                column,
                "external command receives data that appears to come from an uncontrolled source"
                    .to_string(),
                line,
            ),
        );
    }
}

fn controlled_data_names(content: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in content.lines().filter(|line| !is_comment_line(line)) {
        let lower = line.to_ascii_lowercase();
        if let Some((name, value)) = simple_binding(line) {
            if SOURCE_MARKERS.iter().any(|marker| lower.contains(marker))
                || SOURCE_NAME_PARTS.iter().any(|part| name.contains(part))
            {
                push_unique(&mut names, name.to_string());
            } else if names
                .iter()
                .any(|source| contains_identifier(value, source))
            {
                push_unique(&mut names, name.to_string());
            }
        }

        if lower.contains("fn ") {
            let Some((_, params)) = line.split_once('(') else {
                continue;
            };
            let Some((params, _)) = params.split_once(')') else {
                continue;
            };
            for param in params.split(',') {
                let Some((name, _)) = param.split_once(':') else {
                    continue;
                };
                let name = name.trim().trim_start_matches("mut ").trim();
                if SOURCE_NAME_PARTS
                    .iter()
                    .any(|part| name.to_ascii_lowercase().contains(part))
                {
                    push_unique(&mut names, name.to_string());
                }
            }
        }
    }
    names
}

fn simple_binding(line: &str) -> Option<(&str, &str)> {
    let (_, binding) = line.split_once("let ")?;
    let binding = binding
        .trim_start()
        .strip_prefix("mut ")
        .unwrap_or(binding.trim_start());
    let (name, value) = binding.split_once('=')?;
    let name = name.trim().split(':').next()?.trim();
    (!name.is_empty()).then_some((name, value))
}

fn push_unique(names: &mut Vec<String>, name: String) {
    if !names.iter().any(|existing| existing == &name) {
        names.push(name);
    }
}

fn contains_identifier(text: &str, name: &str) -> bool {
    !word_occurrences(text, name).is_empty()
}

fn is_controlled(expression: &str, names: &[String]) -> bool {
    SOURCE_MARKERS
        .iter()
        .any(|marker| expression.contains(marker))
        || SOURCE_NAME_PARTS
            .iter()
            .any(|part| expression.to_ascii_lowercase().contains(part))
        || names
            .iter()
            .any(|name| contains_identifier(expression, name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan(content: &str) -> Vec<Finding> {
        let context = FileContext::new(Path::new("src/main.rs"), content);
        rules()
            .iter()
            .flat_map(|rule| rule.scan(&context))
            .collect()
    }

    #[test]
    fn detects_command_arguments_from_external_sources() {
        let findings = scan(concat!(
            "fn run(user_input: &str) {\n",
            "    Command::new(\"tool\").arg(user_input);\n",
            "}\n",
            "fn from_env() {\n",
            "    let executable = std::env::var(\"TOOL\").unwrap();\n",
            "    Command::new(executable);\n",
            "}\n",
        ));
        assert_eq!(
            findings.iter().map(|item| item.rule_id).collect::<Vec<_>>(),
            ["FE102", "FE102"]
        );
    }

    #[test]
    fn ignores_constant_arguments_and_honors_suppression() {
        assert!(scan("Command::new(\"tool\").arg(\"fixed\");\n").is_empty());
        assert!(
            scan("// fe203-ignore FE102\nCommand::new(\"tool\").arg(user_input);\n").is_empty()
        );
    }
}
