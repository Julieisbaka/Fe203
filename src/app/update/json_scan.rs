pub(super) fn find_asset_download_url(json: &str, names: &[&str]) -> Option<String> {
    for name in names {
        let mut cursor = 0usize;
        while let Some((asset_name, next_pos)) = find_next_key_value(json, "name", cursor) {
            if asset_name == *name {
                if let Some((download_url, _)) =
                    find_next_key_value(json, "browser_download_url", next_pos)
                {
                    return Some(download_url);
                }
            }
            cursor = next_pos;
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
