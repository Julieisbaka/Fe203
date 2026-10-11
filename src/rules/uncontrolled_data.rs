use crate::rules::is_comment_line;
use crate::rules::word_occurrences;

const SOURCE_MARKERS: &[&str] = &[
    "env::var(",
    "env::args(",
    "args_os(",
    "read_line(",
    "stdin(",
    "request.",
    "query.",
    "params.",
];
const SOURCE_NAME_PARTS: &[&str] = &[
    "user", "input", "argument", "request", "query", "command", "arg",
];
const VALIDATION_MARKERS: &[&str] = &["sanitize", "validate", "normalize", "safe_path"];

pub(crate) fn controlled_names(content: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in content.lines().filter(|line| !is_comment_line(line)) {
        let code = code_only(line);
        let lower = code.to_ascii_lowercase();
        if let Some((name, value)) = simple_binding(&code) {
            if !is_validated(value)
                && (has_source_marker(value)
                    || names
                        .iter()
                        .any(|source| !word_occurrences(value, source).is_empty()))
            {
                push_unique(&mut names, name.to_string());
            }
        }

        if lower.contains("fn ") {
            let Some((_, params)) = code.split_once('(') else {
                continue;
            };
            let Some((params, _)) = params.split_once(')') else {
                continue;
            };
            for param in params.split(',') {
                let Some((name, _)) = param.split_once(':') else {
                    continue;
                };
                let name = name.trim().trim_start_matches("mut ").trim();
                if is_source_name(name) {
                    push_unique(&mut names, name.to_string());
                }
            }
        }
    }
    names
}

pub(crate) fn is_controlled(expression: &str, names: &[String]) -> bool {
    let code = code_only(expression);
    has_source_marker(&code)
        || names
            .iter()
            .any(|name| !word_occurrences(&code, name).is_empty())
}

pub(crate) fn is_validated(expression: &str) -> bool {
    let lower = code_only(expression).to_ascii_lowercase();
    VALIDATION_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

pub(crate) fn code_only(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            out.push(' ');
        } else if ch == '"' {
            in_string = true;
            out.push(' ');
        } else if ch == '/' && chars.peek() == Some(&'/') {
            break;
        } else {
            out.push(ch);
        }
    }
    out
}

fn simple_binding(line: &str) -> Option<(&str, &str)> {
    let (_, binding) = line.split_once("let ")?;
    let binding = binding
        .trim_start()
        .strip_prefix("mut ")
        .unwrap_or(binding.trim_start());
    let (name, value) = binding.split_once('=')?;
    let name = name.trim().split(':').next()?.trim();
    (!name.is_empty()).then_some((name, value))
}

fn has_source_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SOURCE_MARKERS.iter().any(|marker| lower.contains(marker))
}

fn is_source_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SOURCE_NAME_PARTS.iter().any(|part| lower.contains(part))
}

fn push_unique(names: &mut Vec<String>, name: String) {
    if !names.iter().any(|existing| existing == &name) {
        names.push(name);
    }
}
