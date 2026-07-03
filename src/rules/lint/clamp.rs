use std::collections::HashSet;

use crate::finding::{Category, Finding, Severity};
use crate::rules::{is_rule_ignored, FileContext, Rule};

/// Detects manual clamp chains like `value.max(min).min(max)`.
pub struct ClampLikePatternRule;

impl Rule for ClampLikePatternRule {
    fn id(&self) -> &'static str {
        "FE060"
    }

    fn name(&self) -> &'static str {
        "manual-clamp"
    }

    fn description(&self) -> &'static str {
        "manual clamp-like min/max chains are harder to read than `.clamp(...)`"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Replace the chained min/max expression with `.clamp(lower, upper)` when the bounds are known.")
    }
    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: v.max(min).min(max)\nafter: v.clamp(min, max)")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &[".max(", ".min("]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for (start_pat, end_pat) in [(".max(", ".min("), (".min(", ".max(")] {
            let mut search_start = 0;
            while let Some(start_rel) = ctx.content[search_start..].find(start_pat) {
                let start_idx = search_start + start_rel;
                let window_end = (start_idx + 240).min(ctx.content.len());
                let window = &ctx.content[start_idx + start_pat.len()..window_end];
                if let Some(end_rel) = window.find(end_pat) {
                    let end_idx = start_idx + start_pat.len() + end_rel;
                    if seen.insert((start_idx, end_idx)) {
                        let (line_no, column) = line_col_at(ctx.content, start_idx);
                        if is_rule_ignored(ctx, line_no, self.id(), self.name(), self.category()) {
                            search_start = start_idx + start_pat.len();
                            continue;
                        }
                        let snippet =
                            snippet_for_range(ctx.content, start_idx, end_idx + end_pat.len());
                        findings.push(self.finding(
                            ctx,
                            line_no,
                            column,
                            "manual clamp-like min/max chain found".to_string(),
                            &snippet,
                        ));
                    }
                    search_start = start_idx + start_pat.len();
                } else {
                    search_start = start_idx + start_pat.len();
                }
            }
        }
        findings
    }
}

fn line_col_at(content: &str, idx: usize) -> (usize, usize) {
    let prefix = &content[..idx];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rfind('\n')
        .map(|pos| prefix[pos + 1..].chars().count() + 1)
        .unwrap_or_else(|| prefix.chars().count() + 1);
    (line, column)
}

fn snippet_for_range(content: &str, start: usize, end: usize) -> String {
    let start = start.saturating_sub(20);
    let end = (end + 20).min(content.len());
    content[start..end].trim().replace('\n', " ")
}
