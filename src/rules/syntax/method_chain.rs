use super::common::{
    build_line_starts, find_matching_delimiter, is_ident_continue, is_ident_start,
    offset_to_line_column, skip_block_comment, skip_char_literal, skip_line_comment,
    skip_raw_string_literal, skip_string_literal,
};
use super::types::{MethodCall, MethodChain};

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
