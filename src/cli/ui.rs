struct TerminalProfile {
    ascii_only: bool,
    narrow: bool,
}

pub fn usage_text() -> String {
    let profile = terminal_profile();
    let dash = if profile.ascii_only { "-" } else { "—" };
    let mut out = String::new();
    out.push_str(&format!(
        "fe203 {dash} a fast, modular scanner and linter for Rust code\n\n"
    ));
    out.push_str("USAGE:\n    fe203 [OPTIONS] [PATH]...\n\n");
    out.push_str("ARGS:\n    [PATH]...    Files or directories to scan\n\n");
    out.push_str("OPTIONS:\n");

    let options = [
        (
            "-c, --config <FILE>",
            "Config file to use (default: ./fe203.toml if present)",
        ),
        (
            "-r, --rules <ID,ID>",
            "Only run these rule IDs (repeatable, e.g. FE001,FE004)",
        ),
        (
            "-g, --categories <A,B>",
            "Only run these categories (repeatable: debug, unsafe, secrets, lint, regex, shell, path)",
        ),
        (
            "-x, --explain <ID>",
            "Show a detailed explanation for one rule (e.g. FE080)",
        ),
        (
            "--init-config [FILE]",
            "Generate a fe203.toml template file (default: ./fe203.toml)",
        ),
        ("-j, --json", "Emit findings as JSON"),
        ("-s, --sarif", "Emit findings as SARIF JSON"),
        (
            "-p, --pretty",
            "Pretty-print JSON/SARIF output (use with --json or --sarif)",
        ),
        (
            "-b, --baseline <FILE>",
            "Suppress findings already present in baseline file",
        ),
        (
            "-B, --init-baseline [FILE]",
            "Write a baseline from current findings (default: ./fe203.baseline)",
        ),
        (
            "--check-syntax",
            "Run cargo check on matching Cargo targets before scanning",
        ),
        (
            "--max",
            "Run all rules and automatically run cargo check + cargo test",
        ),
        ("-l, --list-rules", "List all available rules and exit"),
        ("-h, --help", "Print help"),
        ("-V, --version", "Print version"),
    ];

    for (flag, help) in options {
        if profile.narrow {
            out.push_str(&format!("    {flag}\n        {help}\n"));
        } else {
            out.push_str(&format!("    {:<28} {}\n", flag, help));
        }
    }

    out.push_str("\nEXIT CODES:\n");
    out.push_str("    0    no findings\n");
    out.push_str("    1    findings reported\n");
    out.push_str("    2    usage or configuration error\n");
    out.push_str("\nNOTES:\n");
    out.push_str("    Value flags accept --flag=value in addition to --flag value\n");
    out.push_str("    --rules and --categories can be repeated; values are merged\n");
    out
}

pub fn intro_text() -> String {
    let profile = terminal_profile();
    let dash = if profile.ascii_only { "-" } else { "—" };
    if profile.narrow {
        format!(
            "fe203 {dash} a fast, modular scanner and linter for Rust code\n\nGetting started:\n  fe203 .\n  fe203 src/\n  fe203 --list-rules\n  fe203 --help\n\nTip: run --init-config to create fe203.toml."
        )
    } else {
        format!(
            "fe203 {dash} a fast, modular scanner and linter for Rust code\n\nGetting started:\n    fe203 .                 Scan the current directory\n    fe203 src/              Scan a specific path\n    fe203 --list-rules      Show built-in rules\n    fe203 --help            Show full CLI help\n\nTip: add fe203.toml with --init-config to customize rules and paths."
        )
    }
}

fn terminal_profile() -> TerminalProfile {
    let term = std::env::var("TERM")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let dumb = term == "dumb";
    let ascii_env = std::env::var("FE203_ASCII")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false);
    let no_color = std::env::var("NO_COLOR").is_ok();
    let cols = std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100);

    TerminalProfile {
        ascii_only: dumb || ascii_env,
        narrow: cols < 90 || dumb || no_color,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_text_respects_ascii_env() {
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::set_var("FE203_ASCII", "1");
        }
        let usage = usage_text();
        assert!(usage.contains("fe203 - a fast, modular scanner and linter for Rust code"));
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::remove_var("FE203_ASCII");
        }
    }

    #[test]
    fn usage_text_wraps_narrow_columns() {
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::set_var("COLUMNS", "70");
        }
        let usage = usage_text();
        assert!(usage.contains("--check-syntax\n"));
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::remove_var("COLUMNS");
        }
    }
}
