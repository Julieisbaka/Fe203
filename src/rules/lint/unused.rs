use crate::finding::{Category, Finding, Severity};
use crate::rules::{
    identifier_occurrences_ignoring_comments_and_literals, is_rule_ignored, FileContext, Rule,
};

struct Declaration {
    name: String,
    line_no: usize,
    column: usize,
    start: usize,
    end: usize,
    snippet: String,
}

/// Detects local variables that appear to be declared but never used.
pub struct UnusedVariableRule;

impl Rule for UnusedVariableRule {
    fn id(&self) -> &'static str {
        "FE063"
    }

    fn name(&self) -> &'static str {
        "unused-variable"
    }

    fn description(&self) -> &'static str {
        "unused variables are a sign of dead code or a missed refactor"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Remove the variable or prefix it with an underscore if it is intentionally unused.")
    }
    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: let value = compute();\nafter: let _value = compute();")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["let"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let declarations = collect_declarations(ctx.content, parse_let_binding);
        declarations
            .iter()
            .filter_map(|decl| {
                if is_rule_ignored(ctx, decl.line_no, self.id(), self.name(), self.category()) {
                    return None;
                }
                if has_usage_after_declaration(ctx.content, decl, &declarations) {
                    None
                } else {
                    Some(self.finding(
                        ctx,
                        decl.line_no,
                        decl.column,
                        format!("unused variable `{}`", decl.name),
                        &decl.snippet,
                    ))
                }
            })
            .collect()
    }
}

/// Detects constants that appear to be declared but never used.
pub struct UnusedConstantRule;

impl Rule for UnusedConstantRule {
    fn id(&self) -> &'static str {
        "FE064"
    }

    fn name(&self) -> &'static str {
        "unused-constant"
    }

    fn description(&self) -> &'static str {
        "unused constants often indicate dead code or stale configuration"
    }

    fn category(&self) -> Category {
        Category::Lint
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Remove the constant or use it at every call site that needs it.")
    }
    fn suggestion_example(&self) -> Option<&'static str> {
        Some("before: const MAX_RETRY: usize = 3;\nafter: let retries = MAX_RETRY;")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["const"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let declarations = collect_declarations(ctx.content, parse_const_binding);
        declarations
            .iter()
            .filter_map(|decl| {
                if is_rule_ignored(ctx, decl.line_no, self.id(), self.name(), self.category()) {
                    return None;
                }
                if has_usage_after_declaration(ctx.content, &decl, &declarations) {
                    None
                } else {
                    Some(self.finding(
                        ctx,
                        decl.line_no,
                        decl.column,
                        format!("unused constant `{}`", decl.name),
                        &decl.snippet,
                    ))
                }
            })
            .collect()
    }
}

fn collect_declarations(
    content: &str,
    parse: fn(&str) -> Option<(String, usize)>,
) -> Vec<Declaration> {
    let mut out = Vec::new();
    let mut byte_offset = 0;
    for (idx, line) in content.lines().enumerate() {
        if let Some((name, col_start)) = parse(line) {
            let end = byte_offset + col_start + name.len();
            out.push(Declaration {
                name,
                line_no: idx + 1,
                column: col_start + 1,
                start: byte_offset + col_start,
                end,
                snippet: line.to_string(),
            });
        }
        byte_offset += line.len() + 1;
    }
    out
}

fn parse_let_binding(line: &str) -> Option<(String, usize)> {
    let trimmed = line.trim_start();
    let mut offset = line.len() - trimmed.len();
    let mut rest = trimmed.strip_prefix("let ")?;
    offset += 4;
    let ws = rest.len() - rest.trim_start().len();
    rest = rest.trim_start();
    offset += ws;
    rest = rest.trim_start();
    if let Some(after_mut) = rest.strip_prefix("mut ") {
        rest = after_mut;
        offset += 4;
        let ws = rest.len() - rest.trim_start().len();
        rest = rest.trim_start();
        offset += ws;
    }
    let mut name = String::new();
    for ch in rest.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            name.push(ch);
        } else {
            break;
        }
    }
    if name.is_empty() || name.starts_with('_') {
        return None;
    }
    let tail = rest[name.len()..].trim_start();
    match tail.chars().next() {
        Some(':' | '=' | ';') => Some((name, offset)),
        Some('(' | '{' | '[' | ',') | None => None,
        _ => None,
    }
}

fn parse_const_binding(line: &str) -> Option<(String, usize)> {
    let trimmed = line.trim_start();
    let mut offset = line.len() - trimmed.len();
    let rest = if let Some(after_pub) = trimmed.strip_prefix("pub ") {
        offset += 4;
        after_pub.trim_start()
    } else {
        trimmed
    };
    let ws = rest.len() - rest.trim_start().len();
    let rest = rest.trim_start();
    offset += ws;
    let rest = rest.strip_prefix("const ")?;
    offset += 6;
    let mut name = String::new();
    for ch in rest.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            name.push(ch);
        } else {
            break;
        }
    }
    if name.is_empty() || name.starts_with('_') {
        return None;
    }
    let tail = rest[name.len()..].trim_start();
    match tail.chars().next() {
        Some(':' | '=') => Some((name, offset)),
        _ => None,
    }
}

fn has_usage_after_declaration(
    content: &str,
    decl: &Declaration,
    all_decls: &[Declaration],
) -> bool {
    let occurrences = identifier_occurrences_ignoring_comments_and_literals(content, &decl.name);
    let next_shadow_start = all_decls
        .iter()
        .filter(|d| d.name == decl.name && d.start > decl.start)
        .map(|d| d.start)
        .min()
        .unwrap_or(content.len());

    occurrences.into_iter().any(|pos| {
        if pos <= decl.end || pos >= next_shadow_start {
            return false;
        }
        !all_decls
            .iter()
            .any(|d| d.name == decl.name && pos >= d.start && pos < d.end)
    })
}
