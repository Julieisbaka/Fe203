pub(crate) struct ParsedFunction<'a> {
    pub(crate) line_no: usize,
    pub(crate) end_line: usize,
    pub(crate) header: &'a str,
    pub(crate) body: &'a str,
}

pub(crate) struct Invocation<'a> {
    pub(crate) line_no: usize,
    pub(crate) column: usize,
    pub(crate) path: &'a str,
    pub(crate) kind: InvocationKind,
    pub(crate) args: Option<&'a str>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum InvocationKind {
    Call,
    Macro,
}

pub(crate) fn extract_annotated_functions<'a>(
    content: &'a str,
    attr_markers: &[&str],
) -> Vec<ParsedFunction<'a>> {
    let line_starts = build_line_starts(content);
    let bytes = content.as_bytes();
    let mut idx = 0usize;
    let mut pending_attr_line = None;
    let mut out = Vec::new();

    while idx < bytes.len() {
        match bytes[idx] {
            b'/' if idx + 1 < bytes.len() && bytes[idx + 1] == b'/' => {
                idx = skip_line_comment(bytes, idx + 2);
            }
            b'/' if idx + 1 < bytes.len() && bytes[idx + 1] == b'*' => {
                idx = skip_block_comment(bytes, idx + 2);
            }
            b'#' if idx + 1 < bytes.len() && bytes[idx + 1] == b'[' => {
                let attr_start = idx;
                let attr_end = skip_attribute(bytes, idx + 2);
                let attr_text = &content[attr_start..attr_end];
                if attr_markers.iter().any(|marker| attr_text.contains(marker)) {
                    pending_attr_line = Some(offset_to_line(&line_starts, attr_start));
                }
                idx = attr_end;
            }
            b'"' => idx = skip_string_literal(bytes, idx + 1, b'"'),
            b'\'' => idx = skip_char_literal(bytes, idx + 1),
            b'r' => {
                if let Some(end) = skip_raw_string_literal(bytes, idx) {
                    idx = end;
                } else if starts_with_fn(bytes, idx) {
                    idx = maybe_collect_function(
                        content,
                        &line_starts,
                        bytes,
                        idx,
                        pending_attr_line.take(),
                        &mut out,
                    );
                } else {
                    idx += 1;
                }
            }
            _ if starts_with_fn(bytes, idx) => {
                idx = maybe_collect_function(
                    content,
                    &line_starts,
                    bytes,
                    idx,
                    pending_attr_line.take(),
                    &mut out,
                );
            }
            b if !b.is_ascii_whitespace() => {
                pending_attr_line = None;
                idx += 1;
            }
            _ => idx += 1,
        }
    }

    out
}

pub(crate) fn collect_invocations<'a>(content: &'a str) -> Vec<Invocation<'a>> {
    let line_starts = build_line_starts(content);
    let bytes = content.as_bytes();
    let mut idx = 0usize;
    let mut out = Vec::new();

    while idx < bytes.len() {
        match bytes[idx] {
            b'/' if idx + 1 < bytes.len() && bytes[idx + 1] == b'/' => {
                idx = skip_line_comment(bytes, idx + 2)
            }
            b'/' if idx + 1 < bytes.len() && bytes[idx + 1] == b'*' => {
                idx = skip_block_comment(bytes, idx + 2)
            }
            b'"' => idx = skip_string_literal(bytes, idx + 1, b'"'),
            b'\'' => idx = skip_char_literal(bytes, idx + 1),
            b'r' => {
                if let Some(end) = skip_raw_string_literal(bytes, idx) {
                    idx = end;
                } else if is_ident_start(bytes[idx]) {
                    idx = parse_invocation_from(content, &line_starts, idx, &mut out);
                } else {
                    idx += 1;
                }
            }
            b if is_ident_start(b) => {
                idx = parse_invocation_from(content, &line_starts, idx, &mut out)
            }
            _ => idx += 1,
        }
    }

    out
}

fn maybe_collect_function<'a>(
    content: &'a str,
    line_starts: &[usize],
    bytes: &[u8],
    fn_idx: usize,
    pending_attr_line: Option<usize>,
    out: &mut Vec<ParsedFunction<'a>>,
) -> usize {
    let Some(line_no) = pending_attr_line else {
        return fn_idx + 2;
    };
    let mut cursor = fn_idx + 2;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'/' if cursor + 1 < bytes.len() && bytes[cursor + 1] == b'/' => {
                cursor = skip_line_comment(bytes, cursor + 2)
            }
            b'/' if cursor + 1 < bytes.len() && bytes[cursor + 1] == b'*' => {
                cursor = skip_block_comment(bytes, cursor + 2)
            }
            b'"' => cursor = skip_string_literal(bytes, cursor + 1, b'"'),
            b'\'' => cursor = skip_char_literal(bytes, cursor + 1),
            b'r' => {
                if let Some(end) = skip_raw_string_literal(bytes, cursor) {
                    cursor = end;
                } else if bytes[cursor] == b'{' {
                    break;
                } else {
                    cursor += 1;
                }
            }
            b'{' => break,
            _ => cursor += 1,
        }
    }
    if cursor >= bytes.len() || bytes[cursor] != b'{' {
        return cursor;
    }
    let Some(close) = find_matching_brace(bytes, cursor) else {
        return cursor + 1;
    };
    let end_line = offset_to_line(line_starts, close);
    let header_line_start = line_starts[line_no.saturating_sub(1)];
    let header_line_end = line_starts
        .get(line_no)
        .copied()
        .unwrap_or(content.len())
        .saturating_sub(1);
    out.push(ParsedFunction {
        line_no,
        end_line,
        header: &content[header_line_start..header_line_end],
        body: &content[cursor + 1..close],
    });
    close + 1
}

fn parse_invocation_from<'a>(
    content: &'a str,
    line_starts: &[usize],
    start: usize,
    out: &mut Vec<Invocation<'a>>,
) -> usize {
    let bytes = content.as_bytes();
    let mut cursor = start;
    while cursor < bytes.len() && is_ident_continue(bytes[cursor]) {
        cursor += 1;
    }
    let mut end = cursor;
    loop {
        let mut ws = end;
        while ws < bytes.len() && bytes[ws].is_ascii_whitespace() {
            ws += 1;
        }
        if ws + 1 < bytes.len() && bytes[ws] == b':' && bytes[ws + 1] == b':' {
            let mut next = ws + 2;
            while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                next += 1;
            }
            if next < bytes.len() && is_ident_start(bytes[next]) {
                let mut ident_end = next + 1;
                while ident_end < bytes.len() && is_ident_continue(bytes[ident_end]) {
                    ident_end += 1;
                }
                end = ident_end;
                continue;
            }
        }
        if ws < bytes.len() && bytes[ws] == b'.' {
            let mut next = ws + 1;
            while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                next += 1;
            }
            if next < bytes.len() && is_ident_start(bytes[next]) {
                let mut ident_end = next + 1;
                while ident_end < bytes.len() && is_ident_continue(bytes[ident_end]) {
                    ident_end += 1;
                }
                end = ident_end;
                continue;
            }
        }
        break;
    }

    let mut after = end;
    while after < bytes.len() && bytes[after].is_ascii_whitespace() {
        after += 1;
    }
    if after >= bytes.len() {
        return end;
    }

    match bytes[after] {
        b'!' => {
            let args = if after + 1 < bytes.len() && bytes[after + 1] == b'(' {
                parenthesized_slice(content, after + 1)
            } else {
                None
            };
            let (line_no, column) = offset_to_line_column(line_starts, start);
            out.push(Invocation {
                line_no,
                column,
                path: &content[start..end],
                kind: InvocationKind::Macro,
                args,
            });
            after + 1
        }
        b'(' => {
            let args = parenthesized_slice(content, after);
            let (line_no, column) = offset_to_line_column(line_starts, start);
            out.push(Invocation {
                line_no,
                column,
                path: &content[start..end],
                kind: InvocationKind::Call,
                args,
            });
            after + 1
        }
        _ => end,
    }
}

fn parenthesized_slice(content: &str, open: usize) -> Option<&str> {
    let bytes = content.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let close = find_matching_delimiter(bytes, open, b'(', b')')?;
    Some(&content[open + 1..close])
}

fn find_matching_brace(bytes: &[u8], open: usize) -> Option<usize> {
    find_matching_delimiter(bytes, open, b'{', b'}')
}

fn find_matching_delimiter(
    bytes: &[u8],
    open: usize,
    open_delim: u8,
    close_delim: u8,
) -> Option<usize> {
    let mut depth = 0usize;
    let mut idx = open;
    while idx < bytes.len() {
        match bytes[idx] {
            b'/' if idx + 1 < bytes.len() && bytes[idx + 1] == b'/' => {
                idx = skip_line_comment(bytes, idx + 2)
            }
            b'/' if idx + 1 < bytes.len() && bytes[idx + 1] == b'*' => {
                idx = skip_block_comment(bytes, idx + 2)
            }
            b'"' => idx = skip_string_literal(bytes, idx + 1, b'"'),
            b'\'' => idx = skip_char_literal(bytes, idx + 1),
            b'r' => {
                if let Some(end) = skip_raw_string_literal(bytes, idx) {
                    idx = end;
                } else {
                    idx += 1;
                }
            }
            b if b == open_delim => {
                depth += 1;
                idx += 1;
            }
            b if b == close_delim => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
                idx += 1;
            }
            _ => idx += 1,
        }
    }
    None
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

fn offset_to_line(line_starts: &[usize], offset: usize) -> usize {
    match line_starts.binary_search(&offset) {
        Ok(idx) => idx + 1,
        Err(idx) => idx,
    }
}

fn offset_to_line_column(line_starts: &[usize], offset: usize) -> (usize, usize) {
    let line_no = offset_to_line(line_starts, offset);
    let line_start = line_starts[line_no.saturating_sub(1)];
    (line_no, offset - line_start + 1)
}

fn starts_with_fn(bytes: &[u8], idx: usize) -> bool {
    bytes.get(idx) == Some(&b'f')
        && bytes.get(idx + 1) == Some(&b'n')
        && (idx == 0 || !is_ident_continue(bytes[idx.saturating_sub(1)]))
        && bytes
            .get(idx + 2)
            .is_some_and(|b| b.is_ascii_whitespace() || *b == b'(')
}

fn skip_attribute(bytes: &[u8], mut idx: usize) -> usize {
    let mut depth = 1usize;
    while idx < bytes.len() && depth > 0 {
        match bytes[idx] {
            b'[' => depth += 1,
            b']' => depth -= 1,
            b'"' => idx = skip_string_literal(bytes, idx + 1, b'"'),
            b'\'' => idx = skip_char_literal(bytes, idx + 1),
            b'r' => {
                if let Some(end) = skip_raw_string_literal(bytes, idx) {
                    idx = end;
                    continue;
                }
            }
            _ => {}
        }
        idx += 1;
    }
    idx
}

fn skip_line_comment(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() && bytes[idx] != b'\n' {
        idx += 1;
    }
    idx
}

fn skip_block_comment(bytes: &[u8], mut idx: usize) -> usize {
    let mut depth = 1usize;
    while idx < bytes.len() && depth > 0 {
        if idx + 1 < bytes.len() && bytes[idx] == b'/' && bytes[idx + 1] == b'*' {
            depth += 1;
            idx += 2;
        } else if idx + 1 < bytes.len() && bytes[idx] == b'*' && bytes[idx + 1] == b'/' {
            depth -= 1;
            idx += 2;
        } else {
            idx += 1;
        }
    }
    idx
}

fn skip_string_literal(bytes: &[u8], mut idx: usize, terminator: u8) -> usize {
    while idx < bytes.len() {
        if bytes[idx] == b'\\' {
            idx = (idx + 2).min(bytes.len());
        } else if bytes[idx] == terminator {
            return idx + 1;
        } else {
            idx += 1;
        }
    }
    bytes.len()
}

fn skip_char_literal(bytes: &[u8], idx: usize) -> usize {
    skip_string_literal(bytes, idx, b'\'')
}

fn skip_raw_string_literal(bytes: &[u8], idx: usize) -> Option<usize> {
    if bytes.get(idx) != Some(&b'r') {
        return None;
    }
    let mut hashes = 0usize;
    let mut cursor = idx + 1;
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

fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_ident_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

/// One `.method(args)` link inside a [`MethodChain`].
pub(crate) struct MethodCall<'a> {
    pub(crate) line_no: usize,
    pub(crate) column: usize,
    pub(crate) name: &'a str,
    pub(crate) args: &'a str,
}

/// A root expression (`Command::new("sh")`, `dest`, `crate::run(x)`) followed
/// by zero or more `.method(args)` calls, tracked across lines and comments.
pub(crate) struct MethodChain<'a> {
    pub(crate) line_no: usize,
    pub(crate) column: usize,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) root: &'a str,
    pub(crate) root_args: Option<&'a str>,
    pub(crate) calls: Vec<MethodCall<'a>>,
}

/// Collects method chains from `content`, skipping comments and string
/// literals. Chains with method calls are consumed whole; root-only calls are
/// recorded and their argument interiors re-scanned for nested chains.
pub(crate) fn collect_method_chains(content: &str) -> Vec<MethodChain<'_>> {
    let line_starts = build_line_starts(content);
    let bytes = content.as_bytes();
    let mut idx = 0usize;
    let mut out = Vec::new();

    while idx < bytes.len() {
        match bytes[idx] {
            b'/' if idx + 1 < bytes.len() && bytes[idx + 1] == b'/' => {
                idx = skip_line_comment(bytes, idx + 2)
            }
            b'/' if idx + 1 < bytes.len() && bytes[idx + 1] == b'*' => {
                idx = skip_block_comment(bytes, idx + 2)
            }
            b'"' => idx = skip_string_literal(bytes, idx + 1, b'"'),
            b'\'' => idx = skip_char_literal(bytes, idx + 1),
            b'r' => {
                if let Some(end) = skip_raw_string_literal(bytes, idx) {
                    idx = end;
                } else {
                    idx = parse_chain_from(content, &line_starts, idx, &mut out);
                }
            }
            b if is_ident_start(b) => idx = parse_chain_from(content, &line_starts, idx, &mut out),
            _ => idx += 1,
        }
    }

    out
}

fn parse_chain_from<'a>(
    content: &'a str,
    line_starts: &[usize],
    start: usize,
    out: &mut Vec<MethodChain<'a>>,
) -> usize {
    let bytes = content.as_bytes();
    let mut cursor = start + 1;
    while cursor < bytes.len() && is_ident_continue(bytes[cursor]) {
        cursor += 1;
    }
    while cursor + 1 < bytes.len() && bytes[cursor] == b':' && bytes[cursor + 1] == b':' {
        let mut next = cursor + 2;
        if next < bytes.len() && is_ident_start(bytes[next]) {
            next += 1;
            while next < bytes.len() && is_ident_continue(bytes[next]) {
                next += 1;
            }
            cursor = next;
        } else {
            break;
        }
    }
    let root = &content[start..cursor];
    let after_root = skip_trivia(bytes, cursor);

    let mut end = cursor;
    let mut root_args = None;
    if bytes.get(after_root) == Some(&b'(') {
        let Some(close) = find_matching_delimiter(bytes, after_root, b'(', b')') else {
            return cursor;
        };
        root_args = Some(&content[after_root + 1..close]);
        end = close + 1;
    }

    let mut calls = Vec::new();
    loop {
        let dot = skip_trivia(bytes, end);
        if bytes.get(dot) != Some(&b'.') {
            break;
        }
        let name_start = skip_trivia(bytes, dot + 1);
        if name_start >= bytes.len() || !is_ident_start(bytes[name_start]) {
            break;
        }
        let mut name_end = name_start + 1;
        while name_end < bytes.len() && is_ident_continue(bytes[name_end]) {
            name_end += 1;
        }
        let open = skip_trivia(bytes, name_end);
        if bytes.get(open) != Some(&b'(') {
            break;
        }
        let Some(close) = find_matching_delimiter(bytes, open, b'(', b')') else {
            break;
        };
        let (line_no, column) = offset_to_line_column(line_starts, name_start);
        calls.push(MethodCall {
            line_no,
            column,
            name: &content[name_start..name_end],
            args: &content[open + 1..close],
        });
        end = close + 1;
    }

    if root_args.is_none() && calls.is_empty() {
        return cursor;
    }

    let (line_no, column) = offset_to_line_column(line_starts, start);
    let rescan_inside_args = calls.is_empty();
    out.push(MethodChain {
        line_no,
        column,
        start,
        end,
        root,
        root_args,
        calls,
    });
    if rescan_inside_args {
        // Root-only call: re-scan inside the argument list so nested chains
        // like `run(base.join(user_input))` are still collected.
        after_root + 1
    } else {
        end
    }
}

fn skip_trivia(bytes: &[u8], mut idx: usize) -> usize {
    loop {
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx + 1 < bytes.len() && bytes[idx] == b'/' && bytes[idx + 1] == b'/' {
            idx = skip_line_comment(bytes, idx + 2);
            continue;
        }
        if idx + 1 < bytes.len() && bytes[idx] == b'/' && bytes[idx + 1] == b'*' {
            idx = skip_block_comment(bytes, idx + 2);
            continue;
        }
        return idx;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_test_function_with_braces_in_strings_and_comments() {
        let content = "#[test]\nfn sample() {\n    let _ = \"{ not a block }\";\n    /* { nested } */\n    assert_eq!(2, 1 + 1);\n}\n";
        let functions = extract_annotated_functions(content, &["#[test]"]);
        assert_eq!(functions.len(), 1);
        assert!(functions[0].body.contains("assert_eq!"));
    }

    #[test]
    fn collects_macro_and_call_invocations() {
        let invocations = collect_invocations(
            "assert_eq!(2, crate::parse(\"x\")); Command::new(\"fe203\"); env!(\"CARGO_BIN_EXE_fe203\");",
        );
        assert!(invocations
            .iter()
            .any(|call| call.path == "assert_eq" && call.kind == InvocationKind::Macro));
        assert!(invocations
            .iter()
            .any(|call| call.path == "crate::parse" && call.kind == InvocationKind::Call));
        assert!(invocations
            .iter()
            .any(|call| call.path == "Command::new" && call.kind == InvocationKind::Call));
        assert!(invocations
            .iter()
            .any(|call| call.path == "env" && call.kind == InvocationKind::Macro));
    }

    #[test]
    fn collects_multiline_method_chain_with_comments() {
        let chains = collect_method_chains(
            "Command::new(\"sh\")\n    // interpreter flag\n    .arg(\"-c\")\n    .arg(format!(\"echo {}\", user));\n",
        );
        let chain = chains.iter().find(|c| c.root == "Command::new").unwrap();
        assert_eq!(chain.root_args, Some("\"sh\""));
        let names: Vec<&str> = chain.calls.iter().map(|c| c.name).collect();
        assert_eq!(names, ["arg", "arg"]);
        assert_eq!(chain.calls[1].args, "format!(\"echo {}\", user)");
    }

    #[test]
    fn collects_receiver_chain_and_ignores_string_braces() {
        let chains =
            collect_method_chains("let out = dest.join(entry_name); let s = \"x.join(y)\";\n");
        let chain = chains.iter().find(|c| c.root == "dest").unwrap();
        assert_eq!(chain.calls.len(), 1);
        assert_eq!(chain.calls[0].name, "join");
        assert_eq!(chain.calls[0].args, "entry_name");
        assert_eq!(
            chains
                .iter()
                .filter(|c| c.calls.iter().any(|m| m.name == "join"))
                .count(),
            1
        );
    }

    #[test]
    fn collects_nested_chain_inside_root_call_args() {
        let chains = collect_method_chains("run(base.join(user_input));\n");
        assert!(chains.iter().any(|c| c.root == "run"));
        assert!(chains
            .iter()
            .any(|c| c.root == "base" && c.calls.iter().any(|m| m.name == "join")));
    }
}
