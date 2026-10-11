use crate::finding::{Category, Finding, Severity};
use crate::rules::syntax::{collect_invocations, collect_method_chains, InvocationKind};
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
    vec![Box::new(UncontrolledPathRule)]
}

struct UncontrolledPathRule;

impl Rule for UncontrolledPathRule {
    fn id(&self) -> &'static str {
        "FE125"
    }

    fn name(&self) -> &'static str {
        "uncontrolled-data-in-path"
    }

    fn description(&self) -> &'static str {
        "data from an uncontrolled source is used to construct or access a filesystem path"
    }

    fn category(&self) -> Category {
        Category::Path
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Validate and constrain external path data before using it in filesystem operations.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &[
            ".join(",
            ".push(",
            "PathBuf::from",
            "Path::new",
            "File::open",
            "read_to_string",
            "remove_file",
            "create_dir",
        ]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let tainted = controlled_data_names(ctx.content);
        let lines: Vec<_> = ctx.lines().collect();
        let mut findings = Vec::new();

        for chain in collect_method_chains(ctx.content) {
            for call in chain.calls {
                if matches!(call.name, "join" | "push")
                    && is_controlled(call.args, &tainted)
                    && !looks_validated(call.args)
                {
                    add_finding(self, ctx, &lines, &mut findings, call.line_no, call.column);
                }
            }
        }

        for invocation in collect_invocations(ctx.content) {
            if invocation.kind != InvocationKind::Call {
                continue;
            }
            let is_path_sink = matches!(
                invocation.path.rsplit("::").next(),
                Some(
                    "from"
                        | "new"
                        | "open"
                        | "read"
                        | "read_to_string"
                        | "remove_file"
                        | "create_dir"
                        | "create_dir_all"
                )
            ) && (invocation.path.contains("Path")
                || invocation.path.contains("File")
                || invocation.path.starts_with("std::fs::")
                || invocation.path.starts_with("fs::"));
            let Some(args) = invocation.args else {
                continue;
            };
            if is_path_sink && is_controlled(args, &tainted) && !looks_validated(args) {
                add_finding(
                    self,
                    ctx,
                    &lines,
                    &mut findings,
                    invocation.line_no,
                    invocation.column,
                );
            }
        }
        findings
    }
}

fn add_finding(
    rule: &UncontrolledPathRule,
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
                "filesystem path uses data that appears to come from an uncontrolled source"
                    .to_string(),
                line,
            ),
        );
    }
}

fn controlled_data_names(content: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in content.lines().filter(|line| !is_comment_line(line)) {
        let lower = line.to_ascii_lowercase();
        if let Some((name, value)) = simple_binding(line) {
            if SOURCE_MARKERS.iter().any(|marker| lower.contains(marker))
                || SOURCE_NAME_PARTS.iter().any(|part| name.contains(part))
                || names
                    .iter()
                    .any(|source| !word_occurrences(value, source).is_empty())
            {
                if !names.iter().any(|existing| existing == name) {
                    names.push(name.to_string());
                }
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
                    && !names.iter().any(|existing| existing == name)
                {
                    names.push(name.to_string());
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

fn is_controlled(expression: &str, names: &[String]) -> bool {
    SOURCE_MARKERS
        .iter()
        .any(|marker| expression.contains(marker))
        || SOURCE_NAME_PARTS
            .iter()
            .any(|part| expression.to_ascii_lowercase().contains(part))
        || names
            .iter()
            .any(|name| !word_occurrences(expression, name).is_empty())
}

fn looks_validated(expression: &str) -> bool {
    let lower = expression.to_ascii_lowercase();
    [
        "sanitize",
        "validate",
        "canonicalize",
        "normalize",
        "safe_path",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
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
    fn detects_external_data_flow_into_path_construction_and_filesystem_calls() {
        let findings = scan(concat!(
            "fn load(user_input: &str) {\n",
            "    let path = root.join(user_input);\n",
            "    let file = std::fs::File::open(path);\n",
            "}\n",
            "fn from_args() {\n",
            "    let file_name = std::env::args().nth(1).unwrap();\n",
            "    let path = std::path::PathBuf::from(file_name);\n",
            "}\n",
        ));
        assert_eq!(
            findings.iter().map(|item| item.rule_id).collect::<Vec<_>>(),
            ["FE125", "FE125", "FE125"]
        );
    }

    #[test]
    fn ignores_fixed_or_validated_path_expressions_and_respects_suppression() {
        assert!(scan("let path = root.join(\"assets\");\n").is_empty());
        assert!(scan("let path = root.join(validate_path(user_input)?);\n").is_empty());
        assert!(scan("// fe203-ignore FE125\nlet path = root.join(user_input);\n").is_empty());
    }
}
