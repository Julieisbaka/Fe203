use super::common::{
    build_line_starts, find_matching_brace, is_ident_continue, is_ident_start, offset_to_line,
    offset_to_line_column, parenthesized_slice, skip_attribute, skip_block_comment,
    skip_char_literal, skip_line_comment, skip_raw_string_literal, skip_string_literal,
    starts_with_fn,
};
use super::types::{Invocation, InvocationKind, ParsedFunction};

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
