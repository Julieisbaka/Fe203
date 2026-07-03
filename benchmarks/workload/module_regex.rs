#![allow(dead_code)]

pub fn load_regex_patterns() -> Vec<&'static str> {
    vec![
        "(a+)+$",
        "^.*password.*$",
        "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+",
        "(foo|bar|baz){2,}",
        "^.{8,}$",
        "^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
        "(\\w+\\s*)*",
        "(?:[A-Z][a-z]+){3,}",
        "(?i)token|secret|apikey",
        "(.+)+",
    ]
}

pub fn suspicious_patterns() -> Vec<String> {
    let mut out = Vec::new();
    for pat in load_regex_patterns() {
        if pat.contains("+") && pat.contains("(") {
            out.push(format!("nested:{pat}"));
        }
        if pat.contains(".*") {
            out.push(format!("broad:{pat}"));
        }
        if pat.starts_with('^') && pat.ends_with('$') {
            out.push(format!("anchored:{pat}"));
        }
    }
    out
}

pub fn build_dynamic_regex_fragments(values: &[&str]) -> String {
    let mut pattern = String::from("^");
    for value in values {
        pattern.push_str("(?:");
        pattern.push_str(value);
        pattern.push_str(")?");
    }
    pattern.push('$');
    pattern
}

pub fn scan_inputs(inputs: &[&str]) -> usize {
    let mut score = 0usize;
    for input in inputs {
        if input.contains("token") {
            score += 3;
        }
        if input.contains("secret") {
            score += 5;
        }
        if input.contains("password") {
            score += 7;
        }
        if input.contains("(?i)") {
            score += 2;
        }
        if input.contains(".*") {
            score += 2;
        }
        if input.contains("(.+)+") {
            score += 11;
        }
    }
    score
}

pub fn render_report() -> String {
    let inputs = vec![
        "(?i)token|secret|apikey",
        "^.*password.*$",
        "(.+)+",
        "safe_literal",
        "(a+)+$",
        "^.{8,}$",
        "^[A-Za-z0-9_]+$",
    ];

    let mut out = String::new();
    out.push_str("regex-report\n");
    out.push_str(&format!("score={}\n", scan_inputs(&inputs)));
    for item in suspicious_patterns() {
        out.push_str(&item);
        out.push('\n');
    }
    out
}
