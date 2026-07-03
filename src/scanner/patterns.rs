use std::path::Path;

pub(crate) fn matches_any_pattern(path: &Path, root: &Path, patterns: &[CompiledPattern]) -> bool {
    patterns
        .iter()
        .any(|pattern| matches_pattern(path, root, pattern))
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledPattern {
    cleaned: String,
    has_wildcards: bool,
    has_slash: bool,
}

pub(crate) fn compile_patterns(patterns: &[String]) -> Vec<CompiledPattern> {
    patterns
        .iter()
        .filter_map(|pattern| {
            let cleaned = pattern
                .trim()
                .trim_start_matches("./")
                .trim_end_matches('/')
                .to_string();
            if cleaned.is_empty() {
                return None;
            }
            Some(CompiledPattern {
                has_wildcards: cleaned.contains('*') || cleaned.contains('?'),
                has_slash: cleaned.contains('/'),
                cleaned,
            })
        })
        .collect()
}

fn matches_pattern(path: &Path, root: &Path, pattern: &CompiledPattern) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let basename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let cleaned = pattern.cleaned.as_str();

    if !pattern.has_wildcards && !pattern.has_slash {
        return normalized.split('/').any(|part| part == cleaned) || basename == cleaned;
    }
    if !pattern.has_slash {
        return glob_match_segment(cleaned, basename);
    }

    if let Some(relative) = path
        .strip_prefix(root)
        .ok()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
    {
        if relative == cleaned
            || relative.ends_with(&format!("/{cleaned}"))
            || glob_match_path(cleaned, &relative)
        {
            return true;
        }
    }
    normalized == cleaned
        || normalized.ends_with(&format!("/{cleaned}"))
        || glob_match_path(cleaned, &normalized)
}

fn glob_match_segment(pattern: &str, text: &str) -> bool {
    let pattern_bytes = pattern.as_bytes();
    let text_bytes = text.as_bytes();
    let mut pattern_index = 0;
    let mut text_index = 0;
    let mut star_index = None;
    let mut text_after_star = 0;

    while text_index < text_bytes.len() {
        if pattern_index < pattern_bytes.len()
            && pattern_bytes[pattern_index] != b'*'
            && pattern_bytes[pattern_index] != b'?'
            && pattern_bytes[pattern_index] == text_bytes[text_index]
        {
            pattern_index += 1;
            text_index += 1;
        } else if pattern_index < pattern_bytes.len() && pattern_bytes[pattern_index] == b'?' {
            if text_bytes[text_index] == b'/' {
                return false;
            }
            pattern_index += 1;
            text_index += 1;
        } else if pattern_index < pattern_bytes.len() && pattern_bytes[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            text_after_star = text_index;
        } else if let Some(star) = star_index {
            if text_bytes[text_after_star] == b'/' {
                return false;
            }
            text_after_star += 1;
            text_index = text_after_star;
            pattern_index = star + 1;
        } else {
            return false;
        }
    }

    while pattern_index < pattern_bytes.len() && pattern_bytes[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern_bytes.len()
}

fn glob_match_path(pattern: &str, text: &str) -> bool {
    let pattern_segments: Vec<&str> = pattern
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let text_segments: Vec<&str> = text
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let mut memo = vec![vec![None; text_segments.len() + 1]; pattern_segments.len() + 1];

    fn inner(
        pattern_segments: &[&str],
        text_segments: &[&str],
        pattern_index: usize,
        text_index: usize,
        memo: &mut [Vec<Option<bool>>],
    ) -> bool {
        if let Some(result) = memo[pattern_index][text_index] {
            return result;
        }

        let result = if pattern_index == pattern_segments.len() {
            text_index == text_segments.len()
        } else if pattern_segments[pattern_index] == "**" {
            inner(
                pattern_segments,
                text_segments,
                pattern_index + 1,
                text_index,
                memo,
            ) || (text_index < text_segments.len()
                && inner(
                    pattern_segments,
                    text_segments,
                    pattern_index,
                    text_index + 1,
                    memo,
                ))
        } else if text_index < text_segments.len()
            && glob_match_segment(pattern_segments[pattern_index], text_segments[text_index])
        {
            inner(
                pattern_segments,
                text_segments,
                pattern_index + 1,
                text_index + 1,
                memo,
            )
        } else {
            false
        };

        memo[pattern_index][text_index] = Some(result);
        result
    }

    inner(&pattern_segments, &text_segments, 0, 0, &mut memo)
}
