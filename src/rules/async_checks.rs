use crate::finding::{Category, Finding, Severity};
use crate::rules::syntax::{collect_invocations, InvocationKind};
use crate::rules::{is_comment_line, is_rule_ignored, FileContext, Rule};

const ASYNC_FN_MARKER: &str = "async fn";

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(BlockingInAsyncRule),
        Box::new(LockAcrossAwaitRule),
        Box::new(DetachedTaskRule),
    ]
}

struct BlockingInAsyncRule;

impl Rule for BlockingInAsyncRule {
    fn id(&self) -> &'static str {
        "FE110"
    }

    fn name(&self) -> &'static str {
        "blocking-call-in-async"
    }

    fn description(&self) -> &'static str {
        "blocking standard-library calls can stall an async executor thread"
    }

    fn category(&self) -> Category {
        Category::Async
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Use an async API or move blocking work to an appropriate blocking-task facility.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["async fn", "thread::sleep", "std::fs::", "fs::"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let lines: Vec<_> = ctx.lines().collect();
        let ranges = async_function_ranges(ctx.content);
        collect_invocations(ctx.content)
            .into_iter()
            .filter_map(|invocation| {
                if invocation.kind != InvocationKind::Call
                    || !line_in_ranges(invocation.line_no, &ranges)
                    || !is_blocking_api(invocation.path)
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
                    format!("blocking call `{}` inside async function", invocation.path),
                    line,
                ))
            })
            .collect()
    }
}

struct LockAcrossAwaitRule;

impl Rule for LockAcrossAwaitRule {
    fn id(&self) -> &'static str {
        "FE111"
    }

    fn name(&self) -> &'static str {
        "lock-held-across-await"
    }

    fn description(&self) -> &'static str {
        "holding a synchronous mutex guard across await can block or deadlock tasks"
    }

    fn category(&self) -> Category {
        Category::Async
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some(
            "Limit the guard's scope so it is dropped before awaiting, or use an async-aware lock.",
        )
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &[".lock()", ".await"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let lines: Vec<_> = ctx.lines().collect();
        let content_lines: Vec<_> = ctx.content.lines().collect();
        let mut findings = Vec::new();
        for invocation in collect_invocations(ctx.content) {
            if invocation.kind != InvocationKind::Call
                || invocation.path.rsplit('.').next() != Some("lock")
                || is_rule_ignored(
                    ctx,
                    invocation.line_no,
                    self.id(),
                    self.name(),
                    self.category(),
                )
            {
                continue;
            }
            let Some(line) = line_at(&lines, invocation.line_no) else {
                continue;
            };
            let Some(binding) = line[..invocation.column.saturating_sub(1)]
                .rsplit_once("let ")
                .map(|(_, binding)| {
                    binding
                        .trim()
                        .trim_start_matches("mut ")
                        .trim_end_matches('=')
                })
                .map(str::trim)
                .filter(|binding| is_identifier(binding))
            else {
                continue;
            };
            let start = invocation.line_no.saturating_sub(1);
            let end = enclosing_block_end(&content_lines, start);
            let after_lock = content_lines
                .get(start)
                .map(|text| &text[invocation.column.saturating_sub(1)..])
                .unwrap_or("");
            let mut saw_await = after_lock.contains(".await");
            let mut guard_used_after_await = saw_await && after_lock.contains(binding);
            for later in content_lines.iter().take(end + 1).skip(start + 1) {
                if let Some(await_at) = later.find(".await") {
                    saw_await = true;
                    guard_used_after_await |= later[await_at..].contains(binding);
                } else if saw_await && later.contains(binding) {
                    guard_used_after_await = true;
                }
                if later.contains(&format!("drop({binding})")) {
                    break;
                }
            }
            if saw_await && guard_used_after_await {
                findings.push(self.finding(
                    ctx,
                    invocation.line_no,
                    invocation.column,
                    format!("mutex guard `{binding}` remains in scope across `.await`"),
                    line,
                ));
            }
        }
        findings
    }
}

struct DetachedTaskRule;

impl Rule for DetachedTaskRule {
    fn id(&self) -> &'static str {
        "FE112"
    }

    fn name(&self) -> &'static str {
        "detached-task-handle"
    }

    fn description(&self) -> &'static str {
        "dropping a spawned task handle may hide task failure or skip completion"
    }

    fn category(&self) -> Category {
        Category::Async
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Store and await the task handle, or explicitly document why detaching is intended.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["tokio::spawn", "async_std::task::spawn"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let lines: Vec<_> = ctx.lines().collect();
        collect_invocations(ctx.content)
            .into_iter()
            .filter_map(|invocation| {
                if invocation.kind != InvocationKind::Call
                    || !is_spawn_api(invocation.path)
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
                let before = line.get(..invocation.column.saturating_sub(1))?;
                if before.contains("let ")
                    || line[invocation.column.saturating_sub(1)..].contains(".await")
                    || line[invocation.column.saturating_sub(1)..].contains(".join")
                {
                    return None;
                }
                Some(self.finding(
                    ctx,
                    invocation.line_no,
                    invocation.column,
                    "spawned task handle is not retained or awaited".to_string(),
                    line,
                ))
            })
            .collect()
    }
}

fn async_function_ranges(content: &str) -> Vec<(usize, usize)> {
    let lines: Vec<_> = content.lines().collect();
    let mut ranges = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if !line.contains(ASYNC_FN_MARKER) || is_comment_line(line) {
            continue;
        }
        let start = line.find('{').map(|_| idx).unwrap_or_else(|| {
            (idx + 1..lines.len())
                .find(|next| lines[*next].contains('{'))
                .unwrap_or(idx)
        });
        ranges.push((idx + 1, enclosing_block_end(&lines, start) + 1));
    }
    ranges
}

fn enclosing_block_end(lines: &[&str], start: usize) -> usize {
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

fn is_blocking_api(path: &str) -> bool {
    matches!(path, "std::thread::sleep" | "thread::sleep")
        || path.starts_with("std::fs::")
        || path.starts_with("fs::")
        || path == "std::thread::spawn"
        || path == "thread::spawn"
}

fn is_spawn_api(path: &str) -> bool {
    matches!(
        path,
        "tokio::spawn"
            | "tokio::task::spawn"
            | "async_std::task::spawn"
            | "async_std::task::spawn_local"
    )
}

fn line_at<'a>(lines: &[(usize, &'a str)], line_no: usize) -> Option<&'a str> {
    lines
        .iter()
        .find(|(number, _)| *number == line_no)
        .map(|(_, line)| *line)
}

fn line_in_ranges(line_no: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| line_no >= *start && line_no <= *end)
}

fn is_identifier(input: &str) -> bool {
    !input.is_empty()
        && input
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        && input
            .bytes()
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
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
    fn detects_blocking_calls_only_inside_async_functions() {
        let findings = scan(concat!(
            "fn sync() { std::thread::sleep(duration); }\n",
            "async fn work() {\n",
            "    std::thread::sleep(duration);\n",
            "    std::fs::read(path);\n",
            "}\n",
        ));
        let ids: Vec<&str> = findings.iter().map(|finding| finding.rule_id).collect();
        assert_eq!(ids, ["FE110", "FE110"]);
    }

    #[test]
    fn detects_guard_use_across_await() {
        let findings = scan(
            "async fn work() {\n let guard = mutex.lock().unwrap();\n send().await;\n use_guard(&guard);\n}\n",
        );
        assert!(findings.iter().any(|finding| finding.rule_id == "FE111"));
    }

    #[test]
    fn detects_unretained_spawn_but_not_saved_handle() {
        let findings = scan(concat!(
            "fn work() {\n",
            "    tokio::spawn(task());\n",
            "    let handle = tokio::spawn(task());\n",
            "}\n",
        ));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule_id == "FE112")
                .count(),
            1
        );
    }
}
