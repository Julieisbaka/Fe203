use std::collections::HashSet;

use crate::finding::{Category, Finding, Severity};
use crate::rules::{all_rules, is_rule_ignored, FileContext, Rule};

/// Flags suppression IDs that do not correspond to any rule finding in the file.
pub struct DeadSuppressionCommentRule;

impl Rule for DeadSuppressionCommentRule {
    fn id(&self) -> &'static str {
        "FE066"
    }

    fn name(&self) -> &'static str {
        "dead-suppression-comment"
    }

    fn description(&self) -> &'static str {
        "suppression comments for rule IDs with no matching findings create stale lint policy"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Remove stale fe203-ignore IDs or replace them with active rule IDs.")
    }

    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: // fe203-ignore FE999\nafter: // remove stale suppression")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["fe203-ignore"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let active_ids = unsuppressed_finding_ids(ctx);
        dead_suppression_findings(ctx, &active_ids)
    }
}

pub(crate) fn dead_suppression_findings(
    ctx: &FileContext,
    active_ids: &HashSet<&'static str>,
) -> Vec<Finding> {
    let rule = DeadSuppressionCommentRule;
    let mut findings = Vec::new();

    for directive in suppression_directives(ctx.content) {
        if !looks_like_rule_id(&directive.rule_id) {
            continue;
        }
        if active_ids.contains(directive.rule_id.as_str()) {
            continue;
        }
        if is_rule_ignored(
            ctx,
            directive.line_no,
            rule.id(),
            rule.name(),
            rule.category(),
        ) {
            continue;
        }
        findings.push(rule.finding(
            ctx,
            directive.line_no,
            1,
            format!(
                "suppression for `{}` does not match any finding in this file",
                directive.rule_id
            ),
            &directive.snippet,
        ));
    }

    findings
}

struct SuppressionDirective {
    rule_id: String,
    line_no: usize,
    snippet: String,
}

fn unsuppressed_finding_ids(ctx: &FileContext) -> HashSet<&'static str> {
    let unsuppressed = ctx
        .content
        .replace("fe203-ignore-file", "fe203-note-file")
        .replace("fe203-ignore", "fe203-note");
    let unsuppressed_ctx = FileContext::new(ctx.path, &unsuppressed);
    let mut ids = HashSet::new();
    for rule in all_rules().iter().map(|r| r.as_ref()) {
        if rule.id() == "FE066" {
            continue;
        }
        for finding in rule.scan(&unsuppressed_ctx) {
            ids.insert(finding.rule_id);
        }
    }
    ids
}

fn suppression_directives(content: &str) -> Vec<SuppressionDirective> {
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let Some(comment) = extract_comment_text(line) else {
            continue;
        };
        if let Some((_, rest)) = comment.split_once("fe203-ignore-file") {
            out.extend(tokens_to_directives(rest, line_no, line));
            continue;
        }
        if let Some((_, rest)) = comment.split_once("fe203-ignore") {
            out.extend(tokens_to_directives(rest, line_no, line));
        }
    }
    out
}

fn tokens_to_directives(rest: &str, line_no: usize, line: &str) -> Vec<SuppressionDirective> {
    rest.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| !s.eq_ignore_ascii_case("all"))
        .map(|token| SuppressionDirective {
            rule_id: token.to_ascii_uppercase(),
            line_no,
            snippet: line.to_string(),
        })
        .collect()
}

fn looks_like_rule_id(token: &str) -> bool {
    token.len() == 5
        && token.starts_with("FE")
        && token
            .as_bytes()
            .iter()
            .skip(2)
            .all(|byte| byte.is_ascii_digit())
}

fn extract_comment_text(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if let Some(pos) = trimmed.find("//") {
        return Some(&trimmed[pos + 2..]);
    }
    if let Some(start) = trimmed.find("/*") {
        let rest = &trimmed[start + 2..];
        if let Some(end) = rest.find("*/") {
            return Some(&rest[..end]);
        }
        return Some(rest);
    }
    None
}
