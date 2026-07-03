//! Minimal std-only CLI argument parsing.
// fe203-ignore-file FE020

use std::path::PathBuf;

use crate::rules::Rule;

struct TerminalProfile {
    ascii_only: bool,
    narrow: bool,
}

pub fn usage_text() -> String {
    let profile = terminal_profile();
    let dash = if profile.ascii_only { "-" } else { "—" };
    let mut out = String::new();
    out.push_str(&format!("fe203 {dash} a fast, modular scanner and linter for Rust code\n\n"));
    out.push_str("USAGE:\n    fe203 [OPTIONS] [PATH]...\n\n");
    out.push_str("ARGS:\n    [PATH]...    Files or directories to scan\n\n");
    out.push_str("OPTIONS:\n");

    let options = [
        ("-c, --config <FILE>", "Config file to use (default: ./fe203.toml if present)"),
        ("--rules <ID,ID>", "Only run these rule IDs (e.g. FE001,FE004)"),
        (
            "--categories <A,B>",
            "Only run these categories (debug, unsafe, secrets, lint, regex, shell, path)",
        ),
        ("--explain <ID>", "Show a detailed explanation for one rule (e.g. FE080)"),
        (
            "--init-config [FILE]",
            "Generate a fe203.toml template file (default: ./fe203.toml)",
        ),
        ("--json", "Emit findings as JSON"),
        ("--sarif", "Emit findings as SARIF JSON"),
        ("--pretty", "Pretty-print JSON/SARIF output (use with --json or --sarif)"),
        ("--baseline <FILE>", "Suppress findings already present in baseline file"),
        (
            "--init-baseline [FILE]",
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
        ("--list-rules", "List all available rules and exit"),
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
    let term = std::env::var("TERM").unwrap_or_default().to_ascii_lowercase();
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

#[derive(Debug, Default)]
pub struct CliOptions {
    pub paths: Vec<PathBuf>,
    pub config: Option<PathBuf>,
    pub json: bool,
    pub sarif: bool,
    pub pretty: bool,
    pub list_rules: bool,
    pub explain: Option<String>,
    pub init_config: Option<PathBuf>,
    pub baseline: Option<PathBuf>,
    pub init_baseline: Option<PathBuf>,
    pub check_syntax: bool,
    pub max: bool,
    pub help: bool,
    pub version: bool,
    /// Uppercased rule IDs, if `--rules` was given.
    pub rule_filter: Option<Vec<String>>,
    /// Lowercased category names, if `--categories` was given.
    pub category_filter: Option<Vec<String>>,
}

impl CliOptions {
    /// Whether CLI filters allow this rule to run.
    pub fn allows_rule(&self, rule: &dyn Rule) -> bool {
        if let Some(ids) = &self.rule_filter {
            if !ids.iter().any(|id| id == rule.id()) {
                return false;
            }
        }
        if let Some(categories) = &self.category_filter {
            if !categories.iter().any(|c| c == rule.category().name()) {
                return false;
            }
        }
        true
    }
}

pub fn parse(args: &[String]) -> Result<CliOptions, String> {
    let mut opts = CliOptions::default();
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => opts.help = true,
            "-V" | "--version" => opts.version = true,
            "--json" => opts.json = true,
            "--sarif" => opts.sarif = true,
            "--pretty" => opts.pretty = true,
            "--list-rules" => opts.list_rules = true,
            "--check-syntax" => opts.check_syntax = true,
            "--max" => opts.max = true,
            "--explain" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a rule ID"))?;
                opts.explain = Some(value.to_uppercase());
            }
            "--init-config" => {
                let default_path = PathBuf::from("fe203.toml");
                let next = iter.clone().next();
                if let Some(value) = next {
                    if !value.starts_with('-') {
                        let value = iter.next().expect("iterator advanced after clone check");
                        opts.init_config = Some(PathBuf::from(value));
                        continue;
                    }
                }
                opts.init_config = Some(default_path);
            }
            "--init-baseline" => {
                let default_path = PathBuf::from("fe203.baseline");
                let next = iter.clone().next();
                if let Some(value) = next {
                    if !value.starts_with('-') {
                        let value = iter.next().expect("iterator advanced after clone check");
                        opts.init_baseline = Some(PathBuf::from(value));
                        continue;
                    }
                }
                opts.init_baseline = Some(default_path);
            }
            "--baseline" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a file path"))?;
                opts.baseline = Some(PathBuf::from(value));
            }
            "-c" | "--config" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a file path"))?;
                opts.config = Some(PathBuf::from(value));
            }
            "--rules" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a comma-separated list of rule IDs"))?;
                opts.rule_filter = Some(split_list(value, str::to_uppercase));
            }
            "--categories" => {
                let value = iter.next().ok_or_else(|| {
                    format!("{arg} requires a comma-separated list of categories")
                })?;
                opts.category_filter = Some(split_list(value, str::to_lowercase));
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option: {other}"));
            }
            path => opts.paths.push(PathBuf::from(path)),
        }
    }

    Ok(opts)
}

fn split_list(value: &str, normalize: fn(&str) -> String) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(normalize)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::all_rules;

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
    fn usage_text_respects_narrow_columns() {
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

    #[test]
    fn parses_paths_and_flags() {
        let args: Vec<String> = ["src", "--json", "--config", "custom.toml"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let opts = parse(&args).unwrap();
        assert_eq!(opts.paths, [PathBuf::from("src")]);
        assert!(opts.json);
        assert_eq!(opts.config, Some(PathBuf::from("custom.toml")));
    }

    #[test]
    fn rejects_unknown_option() {
        let args = vec!["--frobnicate".to_string()];
        assert!(parse(&args).is_err());
    }

    #[test]
    fn filters_apply_to_rules() {
        let args: Vec<String> = ["--categories", "secrets"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let opts = parse(&args).unwrap();
        for rule in all_rules() {
            let expected = rule.category().name() == "secrets";
            assert_eq!(opts.allows_rule(rule.as_ref()), expected, "{}", rule.id());
        }
    }

    #[test]
    fn rule_filter_is_case_insensitive() {
        let args: Vec<String> = ["--rules", "fe001"].iter().map(|s| s.to_string()).collect();
        let opts = parse(&args).unwrap();
        let rules = all_rules();
        let todo = rules.iter().find(|r| r.id() == "FE001").unwrap();
        assert!(opts.allows_rule(todo.as_ref()));
    }

    #[test]
    fn parses_explain_and_init_config() {
        let args: Vec<String> = [
            "--explain",
            "fe080",
            "--init-config",
            "--sarif",
            "--pretty",
            "--check-syntax",
            "--max",
            "--baseline",
            "existing.baseline",
            "--init-baseline",
        ]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let opts = parse(&args).unwrap();
        assert_eq!(opts.explain, Some("FE080".to_string()));
        assert_eq!(opts.init_config, Some(PathBuf::from("fe203.toml")));
        assert!(opts.sarif);
        assert!(opts.pretty);
        assert!(opts.check_syntax);
        assert!(opts.max);
        assert_eq!(opts.baseline, Some(PathBuf::from("existing.baseline")));
        assert_eq!(opts.init_baseline, Some(PathBuf::from("fe203.baseline")));
    }
}
