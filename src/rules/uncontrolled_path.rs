use crate::finding::{Category, Finding, Severity};
use crate::rules::syntax::{collect_invocations, collect_method_chains, InvocationKind};
use crate::rules::uncontrolled_data::{controlled_names, is_controlled, is_validated};
use crate::rules::{is_rule_ignored, FileContext, Rule};

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
        let tainted = controlled_names(ctx.content);
        let lines: Vec<_> = ctx.lines().collect();
        let mut findings = Vec::new();

        for chain in collect_method_chains(ctx.content) {
            for call in chain.calls {
                if (call.name == "join"
                    || (call.name == "push" && is_path_receiver(ctx.content, chain.root)))
                    && is_controlled(call.args, &tainted)
                    && !is_validated(call.args)
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
            if is_path_sink && is_controlled(args, &tainted) && !is_validated(args) {
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

fn is_path_receiver(content: &str, receiver: &str) -> bool {
    if receiver.contains("PathBuf")
        || receiver.contains("Path::")
        || receiver.contains("std::path::Path")
    {
        return true;
    }

    let receiver = receiver.trim().trim_start_matches('&').trim();
    if receiver.is_empty()
        || !receiver
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return false;
    }

    content.lines().any(|line| {
        let line = line.trim();
        line.starts_with("let ") && line.contains(receiver) && line.contains("PathBuf")
            || line.contains(&format!("{receiver}: &Path"))
            || line.contains(&format!("{receiver}: &mut Path"))
    })
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
        assert!(scan(concat!(
            "let path = root.join(\"assets\");\n",
            "let input_path = root.join(\"user_input\");\n",
            "let note = \"env::var(user_input)\";\n",
        ))
        .is_empty());
        assert!(scan("let path = root.join(validate_path(user_input)?);\n").is_empty());
        assert!(scan(concat!(
            "fn load(user_input: &str) {\n",
            "    let validated = validate_path(user_input)?;\n",
            "    let path = root.join(validated);\n",
        ))
        .is_empty());
        assert!(scan("// fe203-ignore FE125\nlet path = root.join(user_input);\n").is_empty());
    }

    #[test]
    fn only_treats_push_as_a_path_sink_for_path_receivers() {
        assert!(scan(
            "fn collect(user_input: &str) { let mut values = Vec::new(); values.push(user_input); }\n"
        )
        .is_empty());
        let findings =
            scan("fn extend(path: &mut PathBuf, user_input: &str) { path.push(user_input); }\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE125");
    }
}
