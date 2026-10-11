use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_comment_line, is_rule_ignored, FileContext, Rule};

const FALLIBLE_FILESYSTEM_CALLS: &[&str] = &[
    "std::fs::remove_file(",
    "fs::remove_file(",
    "std::fs::remove_dir(",
    "fs::remove_dir(",
    "std::fs::rename(",
    "fs::rename(",
    "std::fs::write(",
    "fs::write(",
    "std::fs::create_dir(",
    "fs::create_dir(",
    "std::fs::create_dir_all(",
    "fs::create_dir_all(",
];

pub struct IgnoredFilesystemErrorRule;

impl Rule for IgnoredFilesystemErrorRule {
    fn id(&self) -> &'static str {
        "FE067"
    }

    fn name(&self) -> &'static str {
        "ignored-filesystem-error"
    }

    fn description(&self) -> &'static str {
        "discarding filesystem operation results can hide failures"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Handle the `Result` or document why the filesystem failure is safe to ignore.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &[
            "std::fs::remove_file",
            "fs::remove_file",
            "std::fs::remove_dir",
            "fs::remove_dir",
            "std::fs::rename",
            "fs::rename",
            "std::fs::write",
            "fs::write",
            "std::fs::create_dir",
            "fs::create_dir",
        ]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        ctx.lines()
            .filter_map(|(line_no, line)| {
                if is_comment_line(line)
                    || is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category())
                {
                    return None;
                }
                let assignment = line.find("let _")?;
                let after_binding = line[assignment + "let _".len()..].trim_start();
                let remainder = after_binding.strip_prefix('=')?;
                if !FALLIBLE_FILESYSTEM_CALLS
                    .iter()
                    .any(|call| remainder.contains(call))
                {
                    return None;
                }
                Some(self.finding(
                    ctx,
                    line_no,
                    assignment + 1,
                    "filesystem operation result is explicitly discarded".to_string(),
                    line,
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan(content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(Path::new("test.rs"), content);
        IgnoredFilesystemErrorRule.scan(&ctx)
    }

    #[test]
    fn reports_only_explicitly_discarded_filesystem_results() {
        let findings = scan(concat!(
            "let _ = std::fs::remove_file(path);\n",
            "let _result = std::fs::remove_file(path);\n",
            "let result = std::fs::remove_file(path);\n",
        ));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FE067");
    }

    #[test]
    fn honors_suppression_and_ignores_comments() {
        let findings = scan(concat!(
            "// let _ = std::fs::remove_file(path);\n",
            "// fe203-ignore FE067\n",
            "let _ = std::fs::remove_file(path);\n",
        ));
        assert!(findings.is_empty());
    }
}
