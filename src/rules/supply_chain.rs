use std::path::Component;

use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_comment_line, is_rule_ignored, FileContext, Rule};

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(UnpinnedWorkflowReferenceRule)]
}

struct UnpinnedWorkflowReferenceRule;

impl Rule for UnpinnedWorkflowReferenceRule {
    fn id(&self) -> &'static str {
        "FE140"
    }

    fn name(&self) -> &'static str {
        "unpinned-workflow-reference"
    }

    fn description(&self) -> &'static str {
        "GitHub Actions and reusable workflows should be pinned to immutable commit SHAs"
    }

    fn category(&self) -> Category {
        Category::SupplyChain
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Pin remote actions and reusable workflows to a verified full commit SHA.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["uses:"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        if !is_workflow_path(ctx.path) {
            return Vec::new();
        }
        ctx.lines()
            .filter_map(|(line_no, line)| {
                if is_comment_line(line)
                    || is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category())
                    || is_yaml_suppressed(ctx, line_no, self.id(), self.name())
                {
                    return None;
                }
                let trimmed = line.trim().strip_prefix("- ").unwrap_or(line.trim());
                let (key, value) = trimmed.split_once(':')?;
                if key.trim() != "uses" {
                    return None;
                }
                let reference = value
                    .split_once('#')
                    .map_or(value, |(before_comment, _)| before_comment)
                    .trim()
                    .trim_matches(['\'', '"']);
                if reference.starts_with("./") || reference.starts_with("docker://") {
                    return None;
                }
                let (_, revision) = reference.rsplit_once('@')?;
                if is_full_commit_sha(revision) {
                    return None;
                }
                Some(self.finding(
                    ctx,
                    line_no,
                    line.find(reference).unwrap_or(0) + 1,
                    format!("remote workflow reference `{reference}` is not pinned to a full commit SHA"),
                    line,
                ))
            })
            .collect()
    }
}

fn is_workflow_path(path: &std::path::Path) -> bool {
    let components: Vec<_> = path.components().collect();
    components.windows(2).any(|pair| {
        matches!(pair[0], Component::Normal(name) if name.eq_ignore_ascii_case(".github"))
            && matches!(pair[1], Component::Normal(name) if name.eq_ignore_ascii_case("workflows"))
    }) && path.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
    })
}

fn is_full_commit_sha(revision: &str) -> bool {
    revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_yaml_suppressed(ctx: &FileContext, line_no: usize, id: &str, name: &str) -> bool {
    let lines: Vec<_> = ctx.content.lines().collect();
    let target_matches = |text: &str| {
        text.split(|ch: char| ch == ',' || ch.is_whitespace())
            .any(|target| {
                target.eq_ignore_ascii_case("all")
                    || target.eq_ignore_ascii_case(id)
                    || target.eq_ignore_ascii_case(name)
                    || target.eq_ignore_ascii_case(Category::SupplyChain.name())
            })
    };
    lines.iter().any(|line| {
        let comment = line
            .split_once('#')
            .map(|(_, text)| text)
            .unwrap_or("")
            .trim();
        comment
            .split_once("fe203-ignore-file")
            .is_some_and(|(_, targets)| target_matches(targets))
    }) || [line_no.saturating_sub(1), line_no.saturating_sub(2)]
        .into_iter()
        .filter_map(|number| lines.get(number))
        .any(|line| {
            let comment = line
                .split_once('#')
                .map(|(_, text)| text)
                .unwrap_or("")
                .trim();
            let Some((_, targets)) = comment.split_once("fe203-ignore") else {
                return false;
            };
            if targets.starts_with("-file") {
                return false;
            }
            target_matches(targets)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan(path: &str, content: &str) -> Vec<Finding> {
        let context = FileContext::new(Path::new(path), content);
        rules()
            .iter()
            .flat_map(|rule| rule.scan(&context))
            .collect()
    }

    #[test]
    fn flags_tags_and_branches_but_accepts_full_shas_and_local_actions() {
        let findings = scan(
            ".github/workflows/ci.yml",
            concat!(
                "steps:\n",
                "  - uses: actions/checkout@v4\n",
                "  - uses: owner/repo/.github/workflows/ci.yml@main\n",
                "  - uses: actions/setup-rust@0123456789abcdef0123456789abcdef01234567\n",
                "  - uses: ./.github/actions/local\n",
            ),
        );
        assert_eq!(
            findings.iter().map(|item| item.rule_id).collect::<Vec<_>>(),
            ["FE140", "FE140"]
        );
    }

    #[test]
    fn only_scans_github_workflow_files_and_honors_suppression() {
        assert!(scan("src/main.rs", "uses: actions/checkout@v4\n").is_empty());
        assert!(scan(
            ".github/workflows/ci.yaml",
            "# fe203-ignore FE140\nuses: actions/checkout@v4\n"
        )
        .is_empty());
    }
}
