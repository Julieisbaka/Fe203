const REGEX_MARKERS: &[&str] = &[
    "Regex::new(",
    "regex::Regex::new(",
    "RegexBuilder::new(",
    "regex::bytes::Regex::new(",
];

pub(super) struct RegexCallSite {
    pub line_no: usize,
    pub column: usize,
    pub arg: String,
    pub pattern: Option<String>,
}

pub(super) fn regex_call_sites(lines: &[(usize, &str)]) -> Vec<RegexCallSite> {
    let mut found = Vec::new();
    for (idx, (_, line)) in lines.iter().enumerate() {
        if !line.contains("Regex::new(")
            && !line.contains("regex::Regex::new(")
            && !line.contains("RegexBuilder::new(")
            && !line.contains("regex::bytes::Regex::new(")
        {
            continue;
        }

        let statement = statement_from(lines, idx, 6);
        for marker in REGEX_MARKERS {
            let mut start = 0;
            while let Some(pos) = statement[start..].find(marker) {
                let call_idx = start + pos;
                let args_start = call_idx + marker.len();
                if let Some((arg, consumed)) = parenthesized_argument(&statement[args_start..]) {
                    let (line_no, column) = statement_offset_to_line_column(lines, idx, args_start);
                    let trimmed = arg.trim().to_string();
                    let pattern = complete_string_literal(&trimmed);
                    found.push(RegexCallSite {
                        line_no,
                        column,
                        arg: trimmed,
                        pattern,
                    });
                    start = args_start + consumed;
                } else {
                    start = args_start;
                }
            }
        }
    }
    found.sort_by(|a, b| {
        a.line_no
            .cmp(&b.line_no)
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.arg.cmp(&b.arg))
    });
    found.dedup_by(|a, b| a.line_no == b.line_no && a.column == b.column && a.arg == b.arg);
    found
}

pub(super) fn string_literals_in_line(line: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut i = 0;
    let bytes = line.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'"' || bytes[i] == b'r' {
            if let Some((pattern, consumed)) = parse_string_literal_len(&line[i..]) {
                found.push((i + 1, pattern));
                i += consumed;
                continue;
            }
        }
        i += 1;
    }
    found.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    found.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    found
}

pub(super) fn complete_string_literal(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let (pattern, consumed) = parse_string_literal_len(trimmed)?;
    if trimmed[consumed..].trim().is_empty() {
        Some(pattern)
    } else {
        None
    }
}

fn parse_string_literal_len(input: &str) -> Option<(String, usize)> {
    if input.starts_with('"') {
        parse_normal_string(input)
    } else if input.starts_with('r') {
        parse_raw_string(input)
    } else {
        None
    }
}

fn parse_normal_string(input: &str) -> Option<(String, usize)> {
    let mut escaped = false;
    let mut out = String::new();
    for (offset, c) in input[1..].char_indices() {
        if escaped {
            out.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => return Some((out, offset + 2)),
            c => out.push(c),
        }
    }
    None
}

fn parse_raw_string(input: &str) -> Option<(String, usize)> {
    let mut hashes = 0usize;
    let mut chars = input.chars();
    if chars.next()? != 'r' {
        return None;
    }
    while let Some('#') = chars.next() {
        hashes += 1;
    }
    let open = format!("r{}\"", "#".repeat(hashes));
    if !input.starts_with(&open) {
        return None;
    }
    let close = format!("\"{}", "#".repeat(hashes));
    let body = &input[open.len()..];
    let end = body.find(&close)?;
    Some((body[..end].to_string(), open.len() + end + close.len()))
}

pub(super) fn has_nested_quantifier(pattern: &str) -> bool {
    let mut stack = Vec::new();
    let mut escaped = false;
    let mut in_char_class = false;

    for (idx, ch) in pattern.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' => in_char_class = true,
            ']' => in_char_class = false,
            '(' if !in_char_class => stack.push(idx),
            ')' if !in_char_class => {
                if let Some(start) = stack.pop() {
                    let next = pattern[idx + 1..].chars().next();
                    if matches!(next, Some('*' | '+' | '{')) {
                        let group = &pattern[start + 1..idx];
                        if contains_quantifier_outside_char_class(group) {
                            return true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    false
}

pub(super) fn is_suspicious_regex(pattern: &str) -> bool {
    let repeated_wildcard = pattern.contains(".*.*") || pattern.contains(".+.+");
    let broad_contains = pattern.starts_with(".*")
        && pattern.ends_with(".*")
        && (pattern.matches(".*").count() >= 2 || pattern.matches(".+").count() >= 2);
    let empty_alternation = pattern.starts_with('|')
        || pattern.ends_with('|')
        || pattern.contains("||")
        || pattern.contains("(|")
        || pattern.contains("|)");

    repeated_wildcard || broad_contains || empty_alternation
}

pub(super) fn is_anchored(pattern: &str) -> bool {
    pattern.starts_with('^') && pattern.ends_with('$')
}

pub(super) fn looks_like_validation_context_near(lines: &[(usize, &str)], idx: usize) -> bool {
    let context = context_window(lines, idx, 2, 2).to_ascii_lowercase();

    let validation_markers = [
        "valid", "validate", "invalid", "check", "allowed", "email", "username", "slug",
        "password", "token", "field", "match_ok",
    ];
    let search_markers = ["search", "find", "lookup", "grep", "scan for", "contains"];

    let validation_hit = validation_markers
        .iter()
        .any(|marker| context.contains(marker));
    let search_hit = search_markers.iter().any(|marker| context.contains(marker));

    if search_hit && !validation_hit {
        return false;
    }

    validation_hit || !search_hit
}

pub(super) fn looks_like_regex(pattern: &str) -> bool {
    pattern.chars().any(|c| {
        matches!(
            c,
            '[' | ']' | '(' | ')' | '+' | '*' | '?' | '^' | '$' | '\\' | '|' | '{' | '}' | '.'
        )
    })
}

#[cfg(test)]
pub(super) fn scan_all_for_tests(
    content: &str,
    rules: &[Box<dyn crate::rules::Rule>],
) -> Vec<crate::finding::Finding> {
    let ctx = crate::rules::FileContext::new(std::path::Path::new("test.rs"), content);
    rules.iter().flat_map(|rule| rule.scan(&ctx)).collect()
}

pub(super) fn is_dynamic_regex_expr(expr: &str) -> bool {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return false;
    }
    if complete_string_literal(trimmed).is_some() {
        return false;
    }
    if let Some(args) = trimmed
        .strip_prefix("concat!(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return !comma_separated_parts(args)
            .into_iter()
            .all(|part| complete_string_literal(part).is_some());
    }
    true
}

pub(super) fn nearby_regex_patterns(
    lines: &[(usize, &str)],
    idx: usize,
) -> Vec<(usize, usize, String)> {
    let start = idx.saturating_sub(2);
    let end = (idx + 1).min(lines.len().saturating_sub(1));
    regex_call_sites(&lines[start..=end])
        .into_iter()
        .filter_map(|call| {
            call.pattern
                .map(|pattern| (call.line_no, call.column, pattern))
        })
        .collect()
}

fn contains_quantifier_outside_char_class(group: &str) -> bool {
    let mut escaped = false;
    let mut in_char_class = false;
    for ch in group.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' => in_char_class = true,
            ']' => in_char_class = false,
            '*' | '+' | '{' if !in_char_class => return true,
            _ => {}
        }
    }
    false
}

fn statement_from(lines: &[(usize, &str)], idx: usize, max_lines: usize) -> String {
    let mut out = String::new();
    let end = (idx + max_lines).min(lines.len());
    for (_, line) in lines.iter().take(end).skip(idx) {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(line);
        if line.contains(';') {
            break;
        }
    }
    out
}

fn parenthesized_argument(input: &str) -> Option<(String, usize)> {
    let mut depth = 1i32;
    let mut idx = 0usize;
    while idx < input.len() {
        if let Some((_, consumed)) = parse_string_literal_len(&input[idx..]) {
            idx += consumed;
            continue;
        }
        let ch = input[idx..].chars().next()?;
        let width = ch.len_utf8();
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((input[..idx].to_string(), idx + width));
                }
            }
            _ => {}
        }
        idx += width;
    }
    None
}

fn statement_offset_to_line_column(
    lines: &[(usize, &str)],
    idx: usize,
    offset: usize,
) -> (usize, usize) {
    let mut remaining = offset;
    for (line_no, line) in lines.iter().skip(idx) {
        if remaining <= line.len() {
            return (*line_no, remaining + 1);
        }
        remaining = remaining.saturating_sub(line.len() + 1);
    }
    lines
        .get(idx)
        .map(|(line_no, _)| (*line_no, 1))
        .unwrap_or((1, 1))
}

fn comma_separated_parts(input: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut idx = 0usize;
    while idx < input.len() {
        if let Some((_, consumed)) = parse_string_literal_len(&input[idx..]) {
            idx += consumed;
            continue;
        }
        let ch = input[idx..].chars().next().unwrap_or_default();
        let width = ch.len_utf8();
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(input[start..idx].trim());
                start = idx + width;
            }
            _ => {}
        }
        idx += width;
    }
    let tail = input[start..].trim();
    if !tail.is_empty() {
        parts.push(tail);
    }
    parts
}

fn context_window(lines: &[(usize, &str)], idx: usize, before: usize, after: usize) -> String {
    let start = idx.saturating_sub(before);
    let end = (idx + after).min(lines.len().saturating_sub(1));
    let mut out = String::new();
    for (_, line) in lines.iter().take(end + 1).skip(start) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(line);
    }
    out
}
