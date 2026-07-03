use crate::finding::{Category, Finding, Severity};
use crate::rules::{count_identifier_uses, is_rule_ignored, FileContext, Rule};

struct Declaration {
    name: String,
    line_no: usize,
    column: usize,
    start: usize,
    end: usize,
    shadow_start: usize,
    scope_end: usize,
    snippet: String,
}

struct Statement {
    start: usize,
    end: usize,
    text: String,
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
    let line_starts = build_line_starts(content);
    let mut out = Vec::new();
    for statement in collect_binding_statements(content) {
        let scope_end = lexical_scope_end(content, statement.start);
        for (name, rel_start) in parse(&statement.text) {
            let start = statement.start + rel_start;
            let end = start + name.len();
            let (line_no, column) = locate_line_and_column(&line_starts, start);
            out.push(Declaration {
                name,
                line_no,
                column,
                start,
                end,
                shadow_start: statement.end,
                scope_end,
                snippet: line_text(content, &line_starts, line_no).to_string(),
            });
        }
    }
    out
}

fn parse_let_bindings(statement: &str) -> Vec<(String, usize)> {
    let trimmed = statement.trim_start();
    let mut offset = statement.len() - trimmed.len();
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
        return parse_pattern_bindings(pattern, offset);
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

fn parse_pattern_bindings(pattern: &str, base_offset: usize) -> Vec<(String, usize)> {
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

        if matches!(next, Some('(' | '{' | '['))
            && name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        {
            continue;
        }
        if matches!(next, Some(':')) {
            continue;
        }
        if prev.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }

        if !out.iter().any(|(existing, _)| existing == name) {
            out.push((name.to_string(), base_offset + start));
        }
    }

    out
}

fn parse_const_binding(statement: &str) -> Option<(String, usize)> {
    let trimmed = statement.trim_start();
    let mut offset = statement.len() - trimmed.len();
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

    occurrences.into_iter().any(|pos| {
        if pos <= decl.end || pos >= decl.scope_end {
            return false;
        }
        if all_decls.iter().any(|other| {
            other.name == decl.name
                && other.start > decl.start
                && pos >= other.shadow_start
                && pos < other.scope_end
        }) {
            return false;
        }
        !all_decls
            .iter()
            .any(|d| d.name == decl.name && pos >= d.start && pos < d.end)
    })
}

fn collect_binding_statements(content: &str) -> Vec<Statement> {
    let line_starts = build_line_starts(content);
    let mut out = Vec::new();

    for start in line_starts {
        let line = content[start..]
            .split_once('\n')
            .map(|(line, _)| line)
            .unwrap_or(&content[start..]);
        let trimmed = line.trim_start();
        if !trimmed.starts_with("let ")
            && !trimmed.starts_with("let mut ")
            && !trimmed.starts_with("const ")
            && !trimmed.starts_with("pub const ")
        {
            continue;
        }
        let offset = line.len() - trimmed.len();
        let statement_start = start + offset;
        let statement_end = find_statement_end(content, statement_start);
        out.push(Statement {
            start: statement_start,
            end: statement_end,
            text: content[statement_start..statement_end].to_string(),
        });
    }

    out
}

fn build_line_starts(content: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (idx, byte) in content.as_bytes().iter().enumerate() {
        if *byte == b'\n' && idx + 1 < content.len() {
            starts.push(idx + 1);
        }
    }
    starts
}

fn locate_line_and_column(line_starts: &[usize], offset: usize) -> (usize, usize) {
    let line_idx = match line_starts.binary_search(&offset) {
        Ok(idx) => idx,
        Err(idx) => idx.saturating_sub(1),
    };
    let line_start = line_starts[line_idx];
    (line_idx + 1, offset - line_start + 1)
}

fn line_text<'a>(content: &'a str, line_starts: &[usize], line_no: usize) -> &'a str {
    let idx = line_no.saturating_sub(1);
    let start = line_starts[idx];
    let end = line_starts
        .get(idx + 1)
        .copied()
        .unwrap_or(content.len())
        .saturating_sub(1);
    &content[start..end]
}

fn lexical_scope_end(content: &str, start: usize) -> usize {
    let initial_depth = brace_depth_before(content, start);
    let mut depth = initial_depth;
    let bytes = content.as_bytes();
    let mut idx = start;

    while idx < bytes.len() {
        if bytes[idx] == b'/' && idx + 1 < bytes.len() && bytes[idx + 1] == b'/' {
            idx += 2;
            while idx < bytes.len() && bytes[idx] != b'\n' {
                idx += 1;
            }
            continue;
        }
        if bytes[idx] == b'/' && idx + 1 < bytes.len() && bytes[idx + 1] == b'*' {
            idx = skip_block_comment(bytes, idx + 2);
            continue;
        }
        if bytes[idx] == b'"' {
            idx = skip_string_literal(bytes, idx + 1, b'"');
            continue;
        }
        if bytes[idx] == b'\'' {
            idx = skip_char_literal(bytes, idx + 1);
            continue;
        }
        if bytes[idx] == b'r' {
            if let Some(end) = skip_raw_string_literal(bytes, idx) {
                idx = end;
                continue;
            }
        }

        match bytes[idx] {
            b'{' => depth += 1,
            b'}' => {
                if depth == initial_depth {
                    return idx;
                }
                depth -= 1;
            }
            _ => {}
        }
        idx += 1;
    }

    content.len()
}

fn brace_depth_before(content: &str, end: usize) -> usize {
    let bytes = content.as_bytes();
    let mut idx = 0usize;
    let mut depth = 0usize;

    while idx < end && idx < bytes.len() {
        if bytes[idx] == b'/' && idx + 1 < end && bytes[idx + 1] == b'/' {
            idx += 2;
            while idx < end && bytes[idx] != b'\n' {
                idx += 1;
            }
            continue;
        }
        if bytes[idx] == b'/' && idx + 1 < end && bytes[idx + 1] == b'*' {
            idx = skip_block_comment(bytes, idx + 2).min(end);
            continue;
        }
        if bytes[idx] == b'"' {
            idx = skip_string_literal(bytes, idx + 1, b'"').min(end);
            continue;
        }
        if bytes[idx] == b'\'' {
            idx = skip_char_literal(bytes, idx + 1).min(end);
            continue;
        }
        if bytes[idx] == b'r' {
            if let Some(raw_end) = skip_raw_string_literal(bytes, idx) {
                idx = raw_end.min(end);
                continue;
            }
        }

        match bytes[idx] {
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        idx += 1;
    }

    depth
}

fn find_statement_end(content: &str, start: usize) -> usize {
    let bytes = content.as_bytes();
    let mut idx = start;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;

    while idx < bytes.len() {
        if bytes[idx] == b'/' && idx + 1 < bytes.len() && bytes[idx + 1] == b'/' {
            idx += 2;
            while idx < bytes.len() && bytes[idx] != b'\n' {
                idx += 1;
            }
            continue;
        }
        if bytes[idx] == b'/' && idx + 1 < bytes.len() && bytes[idx + 1] == b'*' {
            idx = skip_block_comment(bytes, idx + 2);
            continue;
        }
        if bytes[idx] == b'"' {
            idx = skip_string_literal(bytes, idx + 1, b'"');
            continue;
        }
        if bytes[idx] == b'\'' {
            idx = skip_char_literal(bytes, idx + 1);
            continue;
        }
        if bytes[idx] == b'r' {
            if let Some(raw_end) = skip_raw_string_literal(bytes, idx) {
                idx = raw_end;
                continue;
            }
        }

        match bytes[idx] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b';' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                return idx;
            }
            _ => {}
        }
        idx += 1;
    }

    content.len()
}

fn skip_string_literal(bytes: &[u8], mut index: usize, terminator: u8) -> usize {
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = (index + 2).min(bytes.len());
        } else if bytes[index] == terminator {
            return index + 1;
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn skip_char_literal(bytes: &[u8], index: usize) -> usize {
    skip_string_literal(bytes, index, b'\'')
}

fn skip_raw_string_literal(bytes: &[u8], index: usize) -> Option<usize> {
    if bytes.get(index) != Some(&b'r') {
        return None;
    }
    let mut hashes = 0usize;
    let mut cursor = index + 1;
    while bytes.get(cursor) == Some(&b'#') {
        hashes += 1;
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    cursor += 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            let mut end = cursor + 1;
            let mut seen = 0usize;
            while seen < hashes && bytes.get(end) == Some(&b'#') {
                seen += 1;
                end += 1;
            }
            if seen == hashes {
                return Some(end);
            }
        }
        cursor += 1;
    }
    Some(bytes.len())
}

fn skip_block_comment(bytes: &[u8], mut index: usize) -> usize {
    let mut depth = 1usize;
    while index < bytes.len() && depth > 0 {
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            depth += 1;
            index += 2;
        } else if index + 1 < bytes.len() && bytes[index] == b'*' && bytes[index + 1] == b'/' {
            depth -= 1;
            index += 2;
        } else {
            index += 1;
        }
    }
    index
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

    #[test]
    fn detects_unused_multiline_destructured_binding() {
        let findings = scan_all(
            "let (\n    left,\n    right,\n) = pair();\nprintln!(\"{}\", left);\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("right"));
    }

    #[test]
    fn keeps_outer_use_after_inner_shadow_block() {
        let findings = scan_all(
            "let value = 1;\n{\n    let value = 2;\n    println!(\"{}\", value);\n}\nprintln!(\"{}\", value);\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_unused_nested_struct_pattern_binding() {
        let findings = scan_all(
            "let Foo { left: Some(inner), right } = value;\nprintln!(\"{}\", right);\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("inner"));
    }
}
