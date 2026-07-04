pub(super) fn build_line_starts(content: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (idx, byte) in content.as_bytes().iter().enumerate() {
        if *byte == b'\n' && idx + 1 < content.len() {
            starts.push(idx + 1);
        }
    }
    starts
}

pub(super) fn offset_to_line(line_starts: &[usize], offset: usize) -> usize {
    match line_starts.binary_search(&offset) {
        Ok(idx) => idx + 1,
        Err(idx) => idx,
    }
}

pub(super) fn offset_to_line_column(line_starts: &[usize], offset: usize) -> (usize, usize) {
    let line_no = offset_to_line(line_starts, offset);
    let line_start = line_starts[line_no.saturating_sub(1)];
    (line_no, offset - line_start + 1)
}

pub(super) fn starts_with_fn(bytes: &[u8], idx: usize) -> bool {
    bytes.get(idx) == Some(&b'f')
        && bytes.get(idx + 1) == Some(&b'n')
        && (idx == 0 || !is_ident_continue(bytes[idx.saturating_sub(1)]))
        && bytes
            .get(idx + 2)
            .is_some_and(|b| b.is_ascii_whitespace() || *b == b'(')
}

pub(super) fn find_matching_brace(bytes: &[u8], open: usize) -> Option<usize> {
    find_matching_delimiter(bytes, open, b'{', b'}')
}

pub(super) fn find_matching_delimiter(
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

pub(super) fn parenthesized_slice(content: &str, open: usize) -> Option<&str> {
    let bytes = content.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let close = find_matching_delimiter(bytes, open, b'(', b')')?;
    Some(&content[open + 1..close])
}

pub(super) fn skip_attribute(bytes: &[u8], mut idx: usize) -> usize {
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

pub(super) fn skip_line_comment(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() && bytes[idx] != b'\n' {
        idx += 1;
    }
    idx
}

pub(super) fn skip_block_comment(bytes: &[u8], mut idx: usize) -> usize {
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

pub(super) fn skip_string_literal(bytes: &[u8], mut idx: usize, terminator: u8) -> usize {
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

pub(super) fn skip_char_literal(bytes: &[u8], idx: usize) -> usize {
    skip_string_literal(bytes, idx, b'\'')
}

pub(super) fn skip_raw_string_literal(bytes: &[u8], idx: usize) -> Option<usize> {
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

pub(super) fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

pub(super) fn is_ident_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}
