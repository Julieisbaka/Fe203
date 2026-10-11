use crate::finding::{Category, Finding, Severity};
use crate::rules::syntax::collect_method_chains;
use crate::rules::uncontrolled_data::{controlled_names, is_controlled};
use crate::rules::{is_rule_ignored, FileContext, Rule};

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
        let tainted = controlled_names(ctx.content);
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
        assert!(scan(concat!(
            "Command::new(\"tool\").arg(\"fixed\");\n",
            "Command::new(\"input\").arg(\"fixed user input\");\n",
            "let note = \"env::var(user_input)\";\n",
        ))
        .is_empty());
        assert!(
            scan("// fe203-ignore FE102\nCommand::new(\"tool\").arg(user_input);\n").is_empty()
        );
    }
}
