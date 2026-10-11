pub(super) fn find_asset_download_url(json: &str, names: &[&str]) -> Option<String> {
    let key = json.find("\"assets\"")?;
    let after_key = json.get(key + "\"assets\"".len()..)?;
    let colon = after_key.find(':')?;
    let mut cursor = key + "\"assets\"".len() + colon + 1;
    let bytes = json.as_bytes();

    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'[') {
        return None;
    }
    cursor += 1;

    loop {
        while bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b',')
        {
            cursor += 1;
        }
        match bytes.get(cursor)? {
            b']' => return None,
            b'{' => {
                let end = matching_json_object_end(json, cursor)?;
                let asset = &json[cursor..end];
                let asset_name = extract_json_string_field(asset, "name")?;
                if names.contains(&asset_name.as_str()) {
                    return extract_json_string_field(asset, "browser_download_url");
                }
                cursor = end;
            }
            _ => return None,
        }
    }
}

fn matching_json_object_end(json: &str, start: usize) -> Option<usize> {
    let bytes = json.as_bytes();
    if bytes.get(start) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (idx, &byte) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx + 1);
                }
            }
            _ => {}
        }
    }
    None
}

pub(super) fn extract_json_string_field(json: &str, key: &str) -> Option<String> {
    find_next_key_value(json, key, 0).map(|(value, _)| value)
}

pub(super) fn find_next_key_value(json: &str, key: &str, start: usize) -> Option<(String, usize)> {
    let key_pattern = format!("\"{}\"", key);
    let haystack = json.get(start..)?;
    let rel_idx = haystack.find(&key_pattern)?;
    let key_idx = start + rel_idx;

    let after_key = json.get(key_idx + key_pattern.len()..)?;
    let colon_rel = after_key.find(':')?;
    let mut value_start = key_idx + key_pattern.len() + colon_rel + 1;

    let bytes = json.as_bytes();
    while let Some(byte) = bytes.get(value_start) {
        if !byte.is_ascii_whitespace() {
            break;
        }
        value_start += 1;
    }

    let (value, next_idx) = parse_json_string_at(json, value_start)?;
    Some((value, next_idx))
}

pub(super) fn parse_json_string_at(json: &str, start: usize) -> Option<(String, usize)> {
    let bytes = json.as_bytes();
    if *bytes.get(start)? != b'"' {
        return None;
    }

    let mut out = String::new();
    let mut idx = start + 1;
    while let Some(&byte) = bytes.get(idx) {
        match byte {
            b'\\' => {
                let escaped = *bytes.get(idx + 1)?;
                match escaped {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        // Keep unicode escapes verbatim for robustness in minimal parser.
                        let seq = json.get(idx + 2..idx + 6)?;
                        out.push_str("\\u");
                        out.push_str(seq);
                        idx += 4;
                    }
                    _ => return None,
                }
                idx += 2;
            }
            b'"' => return Some((out, idx + 1)),
            _ => {
                out.push(byte as char);
                idx += 1;
            }
        }
    }

    None
}
