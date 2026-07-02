//! Debug / unfinished-code rules: `todo!`, `unimplemented!`, `dbg!`, `panic!`.
// fe203-ignore-file FE001, FE002, FE003, FE004

use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_comment_line, is_rule_ignored, word_occurrences, FileContext, Rule};

/// Detects invocations of a specific macro, e.g. `todo!(...)`.
pub struct MacroRule {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    macro_name: &'static str,
    severity: Severity,
}

impl Rule for MacroRule {
    fn id(&self) -> &'static str {
        self.id
    }
    fn name(&self) -> &'static str {
        self.name
    }
    fn description(&self) -> &'static str {
        self.description
    }
    fn category(&self) -> Category {
        Category::Debug
    }
    fn severity(&self) -> Severity {
        self.severity
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some(match self.macro_name {
            "todo" | "unimplemented" => "Implement the code path or remove the placeholder macro.",
            "dbg" => "Remove the debug macro or replace it with intentional logging.",
            "panic" => "Prefer returning a Result or handling the error explicitly.",
            _ => return None,
        })
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in ctx.lines() {
            if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                continue;
            }
            if is_comment_line(line) {
                continue;
            }
            for idx in word_occurrences(line, self.macro_name) {
                // Require the next non-whitespace char to be '!' so we match
                // macro invocations, not identifiers that share the name.
                let rest = line[idx + self.macro_name.len()..].trim_start();
                if rest.starts_with('!') {
                    findings.push(self.finding(
                        ctx,
                        line_no,
                        idx + 1,
                        format!("`{}!` macro found", self.macro_name),
                        line,
                    ));
                }
            }
        }
        findings
    }
}

/// All debug/unfinished-code rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(MacroRule {
            id: "FE001",
            name: "todo-macro",
            description: "todo!() marks unfinished code and panics at runtime",
            macro_name: "todo",
            severity: Severity::Warning,
        }),
        Box::new(MacroRule {
            id: "FE002",
            name: "unimplemented-macro",
            description: "unimplemented!() marks unfinished code and panics at runtime",
            macro_name: "unimplemented",
            severity: Severity::Warning,
        }),
        Box::new(MacroRule {
            id: "FE003",
            name: "dbg-macro",
            description: "dbg!() is a debugging aid that should not ship in production code",
            macro_name: "dbg",
            severity: Severity::Warning,
        }),
        Box::new(MacroRule {
            id: "FE004",
            name: "panic-macro",
            description: "panic!() aborts the current thread; prefer recoverable error handling",
            macro_name: "panic",
            severity: Severity::Warning,
        }),
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
    fn detects_each_macro() {
        let findings = scan_all(
            "fn f() {\n    todo!();\n    unimplemented!();\n    dbg!(x);\n    panic!(\"boom\");\n}\n",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE001", "FE002", "FE003", "FE004"]);
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn ignores_identifiers_and_comments() {
        let findings =
            scan_all("// todo!() in a comment\nlet my_todo = 1;\nlet dbgx = dbg_helper();\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn matches_qualified_panic() {
        let findings = scan_all("core::panic!(\"x\");\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE004");
    }

    #[test]
    fn respects_ignore_comments() {
        let findings = scan_all("// fe203-ignore FE001\ntodo!();\n");
        assert!(findings.is_empty());
    }
}
