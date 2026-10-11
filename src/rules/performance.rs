use crate::finding::{Category, Finding, Severity};
use crate::rules::syntax::{collect_invocations, collect_method_chains, InvocationKind};
use crate::rules::{is_comment_line, is_rule_ignored, FileContext, Rule};

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(CloneInLoopRule),
        Box::new(CollectBeforeIteratingRule),
        Box::new(RegexInLoopRule),
        Box::new(FormatPushRule),
    ]
}

struct CloneInLoopRule;

impl Rule for CloneInLoopRule {
    fn id(&self) -> &'static str {
        "FE130"
    }

    fn name(&self) -> &'static str {
        "clone-in-loop"
    }

    fn description(&self) -> &'static str {
        "cloning inside a loop may repeat an expensive allocation"
    }

    fn category(&self) -> Category {
        Category::Performance
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Consider borrowing the value or moving reusable work outside the loop.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["clone"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let lines: Vec<_> = ctx.lines().collect();
        let ranges = loop_ranges(ctx.content);
        collect_invocations(ctx.content)
            .into_iter()
            .filter_map(|invocation| {
                if invocation.kind != InvocationKind::Call
                    || invocation.path.rsplit('.').next() != Some("clone")
                    || !line_in_ranges(invocation.line_no, &ranges)
                    || is_rule_ignored(
                        ctx,
                        invocation.line_no,
                        self.id(),
                        self.name(),
                        self.category(),
                    )
                {
                    return None;
                }
                let line = line_at(&lines, invocation.line_no)?;
                Some(self.finding(
                    ctx,
                    invocation.line_no,
                    invocation.column,
                    "`.clone()` occurs inside a loop".to_string(),
                    line,
                ))
            })
            .collect()
    }
}

struct CollectBeforeIteratingRule;

impl Rule for CollectBeforeIteratingRule {
    fn id(&self) -> &'static str {
        "FE131"
    }

    fn name(&self) -> &'static str {
        "collect-before-iterate"
    }

    fn description(&self) -> &'static str {
        "collecting into a temporary collection only to iterate allocates unnecessarily"
    }

    fn category(&self) -> Category {
        Category::Performance
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Continue the iterator chain directly instead of collecting before iterating.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["collect"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let lines: Vec<_> = ctx.lines().collect();
        collect_method_chains(ctx.content)
            .into_iter()
            .filter_map(|chain| {
                let calls: Vec<_> = chain.calls.iter().collect();
                let collect = calls.iter().position(|call| call.name == "collect")?;
                let iter_after = calls
                    .iter()
                    .skip(collect + 1)
                    .find(|call| call.name == "iter" || call.name == "into_iter")?;
                if is_rule_ignored(
                    ctx,
                    iter_after.line_no,
                    self.id(),
                    self.name(),
                    self.category(),
                ) {
                    return None;
                }
                let line = line_at(&lines, iter_after.line_no)?;
                Some(self.finding(
                    ctx,
                    iter_after.line_no,
                    iter_after.column,
                    "collected iterator is immediately iterated again".to_string(),
                    line,
                ))
            })
            .collect()
    }
}

struct RegexInLoopRule;

impl Rule for RegexInLoopRule {
    fn id(&self) -> &'static str {
        "FE132"
    }

    fn name(&self) -> &'static str {
        "regex-compiled-in-loop"
    }

    fn description(&self) -> &'static str {
        "compiling a regex inside a loop repeats parsing and allocation"
    }

    fn category(&self) -> Category {
        Category::Performance
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Compile the regex once before entering the loop and reuse it.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["Regex::new", "RegexBuilder::new"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let lines: Vec<_> = ctx.lines().collect();
        let ranges = loop_ranges(ctx.content);
        collect_invocations(ctx.content)
            .into_iter()
            .filter_map(|invocation| {
                if invocation.kind != InvocationKind::Call
                    || !matches!(invocation.path.rsplit("::").next(), Some("new"))
                    || !invocation.path.contains("Regex")
                    || !line_in_ranges(invocation.line_no, &ranges)
                    || is_rule_ignored(
                        ctx,
                        invocation.line_no,
                        self.id(),
                        self.name(),
                        self.category(),
                    )
                {
                    return None;
                }
                let line = line_at(&lines, invocation.line_no)?;
                Some(self.finding(
                    ctx,
                    invocation.line_no,
                    invocation.column,
                    "regex is compiled inside a loop".to_string(),
                    line,
                ))
            })
            .collect()
    }
}

struct FormatPushRule;

impl Rule for FormatPushRule {
    fn id(&self) -> &'static str {
        "FE133"
    }

    fn name(&self) -> &'static str {
        "format-then-push"
    }

    fn description(&self) -> &'static str {
        "formatting a temporary string only to append it causes an avoidable allocation"
    }

    fn category(&self) -> Category {
        Category::Performance
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Use `write!` with a string buffer or append the pieces directly.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["push_str", "format!"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let lines: Vec<_> = ctx.lines().collect();
        collect_invocations(ctx.content)
            .into_iter()
            .filter_map(|invocation| {
                if invocation.kind != InvocationKind::Call
                    || invocation.path.rsplit('.').next() != Some("push_str")
                    || !invocation.args.is_some_and(|args| args.contains("format!"))
                    || is_rule_ignored(
                        ctx,
                        invocation.line_no,
                        self.id(),
                        self.name(),
                        self.category(),
                    )
                {
                    return None;
                }
                let line = line_at(&lines, invocation.line_no)?;
                Some(self.finding(
                    ctx,
                    invocation.line_no,
                    invocation.column,
                    "`format!` creates a temporary string that is immediately appended".to_string(),
                    line,
                ))
            })
            .collect()
    }
}

fn loop_ranges(content: &str) -> Vec<(usize, usize)> {
    let lines: Vec<_> = content.lines().collect();
    lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            if is_comment_line(line) || !starts_loop(line) {
                return None;
            }
            let open_idx = if line.contains('{') {
                idx
            } else {
                (idx + 1..lines.len()).find(|next| lines[*next].contains('{'))?
            };
            Some((idx + 1, block_end(&lines, open_idx) + 1))
        })
        .collect()
}

fn starts_loop(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("for ") || trimmed.starts_with("while ") || trimmed == "loop"
}

fn block_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0usize;
    let mut began = false;
    for (idx, line) in lines.iter().enumerate().skip(start) {
        if is_comment_line(line) {
            continue;
        }
        for byte in line.bytes() {
            if byte == b'{' {
                began = true;
                depth += 1;
            } else if byte == b'}' && began {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return idx;
                }
            }
        }
    }
    lines.len().saturating_sub(1)
}

fn line_at<'a>(lines: &[(usize, &'a str)], number: usize) -> Option<&'a str> {
    lines
        .iter()
        .find(|(line_no, _)| *line_no == number)
        .map(|(_, line)| *line)
}

fn line_in_ranges(line_no: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| line_no >= *start && line_no <= *end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan(content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(Path::new("src/lib.rs"), content);
        rules().iter().flat_map(|rule| rule.scan(&ctx)).collect()
    }

    #[test]
    fn detects_clone_and_regex_compilation_inside_loops_only() {
        let findings = scan(concat!(
            "for item in items {\n",
            "    let copy = item.clone();\n",
            "    let re = Regex::new(\"x+\").unwrap();\n",
            "}\n",
            "let re = Regex::new(\"x+\").unwrap();\n",
        ));
        let ids: Vec<&str> = findings.iter().map(|finding| finding.rule_id).collect();
        assert_eq!(ids, ["FE130", "FE132"]);
    }

    #[test]
    fn detects_collect_then_iterate_and_format_push() {
        let findings = scan(concat!(
            "let values = items.collect().iter().count();\n",
            "buffer.push_str(&format!(\"{}\", value));\n",
        ));
        let ids: Vec<&str> = findings.iter().map(|finding| finding.rule_id).collect();
        assert_eq!(ids, ["FE131", "FE133"]);
    }
}
