//! Minimal std-only CLI argument parsing.

use std::path::PathBuf;

use crate::rules::Rule;

pub const USAGE: &str = "\
fe203 — a fast, modular scanner and linter for Rust code

USAGE:
    fe203 [OPTIONS] [PATH]...

ARGS:
    [PATH]...    Files or directories to scan (default: current directory)

OPTIONS:
    -c, --config <FILE>        Config file to use (default: ./fe203.toml if present)
        --rules <ID,ID>        Only run these rule IDs (e.g. FE001,FE004)
        --categories <A,B>     Only run these categories (debug, unsafe, secrets, lint, regex)
        --json                 Emit findings as JSON
        --list-rules           List all available rules and exit
    -h, --help                 Print help
    -V, --version              Print version

EXIT CODES:
    0    no findings
    1    findings reported
    2    usage or configuration error";

#[derive(Debug, Default)]
pub struct CliOptions {
    pub paths: Vec<PathBuf>,
    pub config: Option<PathBuf>,
    pub json: bool,
    pub list_rules: bool,
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
            "--list-rules" => opts.list_rules = true,
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
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a comma-separated list of categories"))?;
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
        let args: Vec<String> = ["--categories", "secrets"].iter().map(|s| s.to_string()).collect();
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
}
