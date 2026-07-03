use crate::finding::{Category, Finding, Severity};
use crate::rules::{count_identifier_uses, is_rule_ignored, FileContext, Rule};

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
        let declarations = collect_declarations(ctx.content, parse_let_bindings);
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
        let declarations = collect_declarations(ctx.content, parse_const_bindings);
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
    parse: fn(&str) -> Vec<(String, usize)>,
) -> Vec<Declaration> {
    let mut out = Vec::new();
    let mut byte_offset = 0;
    for (idx, line) in content.lines().enumerate() {
        for (name, col_start) in parse(line) {
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

fn parse_let_bindings(line: &str) -> Vec<(String, usize)> {
    let trimmed = line.trim_start();
    let mut offset = line.len() - trimmed.len();
    let Some(mut rest) = trimmed.strip_prefix("let ") else {
        return Vec::new();
    };
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
    let binding_end = rest.find('=').unwrap_or(rest.len());
    let pattern = rest[..binding_end].trim_end();

    if pattern.contains(['(', '{', '[', ',']) {
        return parse_pattern_bindings(pattern, line, offset);
    }

    let mut name = String::new();
    for ch in pattern.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            name.push(ch);
        } else {
            break;
        }
    }
    if name.is_empty() || name.starts_with('_') {
        Vec::new()
    } else {
        vec![(name, offset)]
    }
}

fn parse_pattern_bindings(pattern: &str, line: &str, base_offset: usize) -> Vec<(String, usize)> {
    let bytes = pattern.as_bytes();
    let mut out = Vec::new();
    let mut idx = 0usize;

    while idx < bytes.len() {
        let ch = bytes[idx] as char;
        if !(ch == '_' || ch.is_ascii_alphabetic()) {
            idx += 1;
            continue;
        }

        let start = idx;
        idx += 1;
        while idx < bytes.len() {
            let next = bytes[idx] as char;
            if next == '_' || next.is_ascii_alphanumeric() {
                idx += 1;
            } else {
                break;
            }
        }

        let name = &pattern[start..idx];
        if name == "mut" || name == "ref" || name == "pub" || name.starts_with('_') {
            continue;
        }

        let prev = pattern[..start].chars().rev().find(|c| !c.is_whitespace());
        let next = pattern[idx..].chars().find(|c| !c.is_whitespace());

        if matches!(next, Some('(')) && name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
            continue;
        }
        if matches!(next, Some(':')) {
            continue;
        }
        if prev.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }

        let column = line.find(name).unwrap_or(start + base_offset) + 1;
        if !out.iter().any(|(existing, _)| existing == name) {
            out.push((name.to_string(), column - 1));
        }
    }

    out
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

fn parse_const_bindings(line: &str) -> Vec<(String, usize)> {
    parse_const_binding(line).into_iter().collect()
}

fn has_usage_after_declaration(
    content: &str,
    decl: &Declaration,
    all_decls: &[Declaration],
) -> bool {
    let occurrences = count_identifier_uses(content, &decl.name);
    let next_shadow_end = all_decls
        .iter()
        .filter(|d| d.name == decl.name && d.start > decl.start)
        .map(|d| d.start + d.snippet.len())
        .min()
        .unwrap_or(content.len());

    occurrences.into_iter().any(|pos| {
        if pos <= decl.end || pos >= next_shadow_end {
            return false;
        }
        !all_decls
            .iter()
            .any(|d| d.name == decl.name && pos >= d.start && pos < d.end)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan_all(content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(Path::new("test.rs"), content);
        vec![Box::new(UnusedVariableRule) as Box<dyn Rule>, Box::new(UnusedConstantRule)]
            .iter()
            .flat_map(|rule| rule.scan(&ctx))
            .collect()
    }

    #[test]
    fn detects_unused_destructured_binding() {
        let findings = scan_all("let (left, right) = (1, 2);\nprintln!(\"{}\", left);\n");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, ["FE063"]);
        assert!(findings[0].message.contains("right"));
    }

    #[test]
    fn ignores_used_shadow_chain() {
        let findings = scan_all(
            "let value = 1;\nlet value = value + 1;\nlet value = value + 1;\nprintln!(\"{}\", value);\n",
        );
        assert!(findings.is_empty());
    }
}
