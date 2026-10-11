use crate::finding::{Category, Finding, Severity};
use crate::rules::syntax::{collect_invocations, extract_annotated_functions, InvocationKind};
use crate::rules::{is_rule_ignored, FileContext, Rule};

const TEST_ATTRIBUTES: &[&str] = &[
    "#[test]",
    "#[tokio::test]",
    "#[actix_rt::test]",
    "#[actix_web::test]",
    "#[async_std::test]",
];

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ResultUnwrapOrDefaultRule),
        Box::new(DiscardedFallibleCallRule),
        Box::new(VagueExpectMessageRule),
        Box::new(IgnoredTestRule),
        Box::new(EmptyTestRule),
        Box::new(TautologicalAssertionRule),
        Box::new(SleepInTestRule),
    ]
}

struct ResultUnwrapOrDefaultRule;

impl Rule for ResultUnwrapOrDefaultRule {
    fn id(&self) -> &'static str {
        "FE068"
    }
    fn name(&self) -> &'static str {
        "result-unwrap-or-default"
    }
    fn description(&self) -> &'static str {
        "using a default after a fallible operation can hide an error as valid empty data"
    }
    fn category(&self) -> Category {
        Category::Lint
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some(
            "Handle or propagate the error explicitly rather than silently substituting a default.",
        )
    }
    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["unwrap_or_default"]
    }
    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        const FALLIBLE_CONTEXT: &[&str] = &[
            "read_to_string",
            "read(",
            "parse(",
            "from_str(",
            "env::var(",
            "metadata(",
            "canonicalize(",
        ];
        let lines: Vec<_> = ctx.lines().collect();
        collect_invocations(ctx.content)
            .into_iter()
            .filter_map(|invocation| {
                if invocation.kind != InvocationKind::Call
                    || invocation.path.rsplit('.').next() != Some("unwrap_or_default")
                    || !FALLIBLE_CONTEXT
                        .iter()
                        .any(|marker| ctx.content.contains(marker))
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
                    "default value may conceal a fallible operation's error".to_string(),
                    line,
                ))
            })
            .collect()
    }
}

struct DiscardedFallibleCallRule;

impl Rule for DiscardedFallibleCallRule {
    fn id(&self) -> &'static str {
        "FE069"
    }
    fn name(&self) -> &'static str {
        "discarded-fallible-call"
    }
    fn description(&self) -> &'static str {
        "discarding common I/O and transaction results can hide failed operations"
    }
    fn category(&self) -> Category {
        Category::Lint
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some("Check, propagate, or explicitly handle the operation's result.")
    }
    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &[
            "write_all",
            ".send(",
            ".execute(",
            ".commit(",
            ".flush(",
            ".sync_all(",
        ]
    }
    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        const FALLIBLE_METHODS: &[&str] = &[
            "write_all",
            "send",
            "execute",
            "commit",
            "flush",
            "sync_all",
        ];
        let lines: Vec<_> = ctx.lines().collect();
        collect_invocations(ctx.content)
            .into_iter()
            .filter_map(|invocation| {
                if invocation.kind != InvocationKind::Call
                    || !FALLIBLE_METHODS.contains(&invocation.path.rsplit('.').next().unwrap_or(""))
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
                let prefix = line
                    .get(..invocation.column.saturating_sub(1))?
                    .trim_start();
                if prefix.starts_with("let ")
                    || prefix.starts_with("return ")
                    || prefix.starts_with("if ")
                    || prefix.starts_with("while ")
                    || prefix.starts_with("match ")
                    || line[invocation.column.saturating_sub(1)..].contains('?')
                    || line.contains(".unwrap(")
                    || line.contains(".expect(")
                {
                    return None;
                }
                Some(self.finding(
                    ctx,
                    invocation.line_no,
                    invocation.column,
                    format!("result from `{}` is not handled", invocation.path),
                    line,
                ))
            })
            .collect()
    }
}

struct VagueExpectMessageRule;

impl Rule for VagueExpectMessageRule {
    fn id(&self) -> &'static str {
        "FE070"
    }
    fn name(&self) -> &'static str {
        "vague-expect-message"
    }
    fn description(&self) -> &'static str {
        "generic expect messages provide little context when an operation fails"
    }
    fn category(&self) -> Category {
        Category::Lint
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some("Explain which operation failed and include useful context such as the path or key.")
    }
    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &[".expect("]
    }
    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        const VAGUE: &[&str] = &[
            "\"ok\"",
            "\"success\"",
            "\"works\"",
            "\"should work\"",
            "\"failed\"",
            "\"TODO\"",
            "\"FIXME\"",
            "\"valid\"",
        ];
        let lines: Vec<_> = ctx.lines().collect();
        collect_invocations(ctx.content)
            .into_iter()
            .filter_map(|invocation| {
                if invocation.kind != InvocationKind::Call
                    || invocation.path.rsplit('.').next() != Some("expect")
                    || !invocation
                        .args
                        .is_some_and(|args| VAGUE.iter().any(|message| args.trim() == *message))
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
                Some(self.finding(
                    ctx,
                    invocation.line_no,
                    invocation.column,
                    "generic `expect` message provides little failure context".to_string(),
                    line_at(&lines, invocation.line_no)?,
                ))
            })
            .collect()
    }
}

struct IgnoredTestRule;

impl Rule for IgnoredTestRule {
    fn id(&self) -> &'static str {
        "FE071"
    }
    fn name(&self) -> &'static str {
        "ignored-test"
    }
    fn description(&self) -> &'static str {
        "ignored tests are not run during the normal test suite"
    }
    fn category(&self) -> Category {
        Category::Lint
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some("Remove `#[ignore]` when the test is ready, or document the required reason explicitly.")
    }
    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["#[ignore]"]
    }
    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let lines: Vec<_> = ctx.lines().collect();
        lines
            .iter()
            .enumerate()
            .filter_map(|(idx, (line_no, line))| {
                if !line.trim().starts_with("#[ignore")
                    || is_rule_ignored(ctx, *line_no, self.id(), self.name(), self.category())
                {
                    return None;
                }
                let end = (idx + 4).min(lines.len());
                let is_test = lines[idx + 1..end]
                    .iter()
                    .any(|(_, text)| TEST_ATTRIBUTES.iter().any(|attr| text.contains(attr)));
                is_test.then(|| {
                    self.finding(
                        ctx,
                        *line_no,
                        line.find("#[ignore").unwrap_or(0) + 1,
                        "test is excluded from the normal test suite".to_string(),
                        line,
                    )
                })
            })
            .collect()
    }
}

struct EmptyTestRule;

impl Rule for EmptyTestRule {
    fn id(&self) -> &'static str {
        "FE072"
    }
    fn name(&self) -> &'static str {
        "empty-test"
    }
    fn description(&self) -> &'static str {
        "empty test bodies provide no behavioral coverage"
    }
    fn category(&self) -> Category {
        Category::Lint
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some("Add an assertion about behavior or remove the placeholder test.")
    }
    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["#[test]", "#[tokio::test]"]
    }
    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        extract_annotated_functions(ctx.content, TEST_ATTRIBUTES)
            .into_iter()
            .filter_map(|test| {
                let executable = test
                    .body
                    .lines()
                    .map(|line| line.split("//").next().unwrap_or("").trim())
                    .filter(|line| !line.is_empty())
                    .collect::<String>();
                if !executable.is_empty()
                    || is_rule_ignored(ctx, test.line_no, self.id(), self.name(), self.category())
                {
                    return None;
                }
                Some(self.finding(
                    ctx,
                    test.line_no,
                    1,
                    "test function has an empty body".to_string(),
                    test.header,
                ))
            })
            .collect()
    }
}

struct TautologicalAssertionRule;

impl Rule for TautologicalAssertionRule {
    fn id(&self) -> &'static str {
        "FE073"
    }
    fn name(&self) -> &'static str {
        "tautological-assertion"
    }
    fn description(&self) -> &'static str {
        "assertions that compare a value to itself or a literal truth value cannot fail"
    }
    fn category(&self) -> Category {
        Category::Lint
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some("Assert on the result of the operation under test instead of a constant or identical expression.")
    }
    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["assert!"]
    }
    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let lines: Vec<_> = ctx.lines().collect();
        let test_ranges = extract_annotated_functions(ctx.content, TEST_ATTRIBUTES)
            .into_iter()
            .map(|test| (test.line_no, test.end_line))
            .collect::<Vec<_>>();
        collect_invocations(ctx.content)
            .into_iter()
            .filter_map(|invocation| {
                if invocation.kind != InvocationKind::Macro
                    || !matches!(
                        invocation.path.rsplit("::").next(),
                        Some("assert" | "assert_eq" | "assert_ne")
                    )
                    || !line_in_ranges(invocation.line_no, &test_ranges)
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
                let args = invocation.args?.trim();
                let tautology = if invocation.path.ends_with("assert") {
                    matches!(args, "true" | "false")
                } else {
                    let mut parts = args.splitn(2, ',').map(str::trim);
                    let left = parts.next()?;
                    let right = parts.next()?;
                    left == right
                };
                if !tautology {
                    return None;
                }
                Some(self.finding(
                    ctx,
                    invocation.line_no,
                    invocation.column,
                    "assertion compares constants or an expression with itself".to_string(),
                    line_at(&lines, invocation.line_no)?,
                ))
            })
            .collect()
    }
}

struct SleepInTestRule;

impl Rule for SleepInTestRule {
    fn id(&self) -> &'static str {
        "FE074"
    }
    fn name(&self) -> &'static str {
        "sleep-in-test"
    }
    fn description(&self) -> &'static str {
        "sleep-based timing in tests can make the suite slow and flaky"
    }
    fn category(&self) -> Category {
        Category::Lint
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn suggestion(&self) -> Option<&'static str> {
        Some("Use synchronization primitives, controlled clocks, or explicit async test coordination.")
    }
    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["thread::sleep", "time::sleep"]
    }
    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let lines: Vec<_> = ctx.lines().collect();
        let ranges = extract_annotated_functions(ctx.content, TEST_ATTRIBUTES)
            .into_iter()
            .map(|test| (test.line_no, test.end_line))
            .collect::<Vec<_>>();
        collect_invocations(ctx.content)
            .into_iter()
            .filter_map(|invocation| {
                if invocation.kind != InvocationKind::Call
                    || !is_sleep_call(invocation.path)
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
                Some(self.finding(
                    ctx,
                    invocation.line_no,
                    invocation.column,
                    "test uses a timing-based sleep".to_string(),
                    line_at(&lines, invocation.line_no)?,
                ))
            })
            .collect()
    }
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

fn is_sleep_call(path: &str) -> bool {
    matches!(
        path,
        "std::thread::sleep" | "thread::sleep" | "tokio::time::sleep" | "async_std::task::sleep"
    ) || path.ends_with("::time::sleep")
}

#[cfg(test)]
#[path = "test_quality/tests.rs"]
mod tests;
