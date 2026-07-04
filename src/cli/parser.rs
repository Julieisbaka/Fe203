use std::path::PathBuf;

use crate::rules::Rule;

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
    /// Iteration count when benchmarking is enabled via --benchmark.
    pub benchmark_iterations: Option<usize>,
    pub check_update: bool,
    pub self_update: bool,
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
            "-j" | "--json" => opts.json = true,
            "-s" | "--sarif" => opts.sarif = true,
            "-p" | "--pretty" => opts.pretty = true,
            "-l" | "--list-rules" => opts.list_rules = true,
            "--check-syntax" => opts.check_syntax = true,
            "--max" => opts.max = true,
            "--benchmark" => {
                let mut iterations = 5usize;
                if let Some(value) = iter.clone().next() {
                    if !value.starts_with('-') {
                        if let Ok(parsed) = value.parse::<usize>() {
                            if parsed > 0 {
                                iterations = parsed;
                                let _ = iter.next();
                            }
                        }
                    }
                }
                opts.benchmark_iterations = Some(iterations);
            }
            "--check-update" => opts.check_update = true,
            "--self-update" => opts.self_update = true,
            other if other.starts_with("--benchmark=") => {
                let value = other
                    .split_once('=')
                    .map(|(_, v)| v)
                    .unwrap_or_default()
                    .trim();
                if value.is_empty() {
                    return Err(
                        "--benchmark requires a positive iteration count when using =".to_string(),
                    );
                }
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| "--benchmark requires a positive integer".to_string())?;
                if parsed == 0 {
                    return Err("--benchmark requires a positive integer".to_string());
                }
                opts.benchmark_iterations = Some(parsed);
            }
            "-x" | "--explain" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a rule ID"))?;
                opts.explain = Some(value.to_uppercase());
            }
            other if other.starts_with("--explain=") => {
                let value = other
                    .split_once('=')
                    .map(|(_, v)| v)
                    .unwrap_or_default()
                    .trim();
                if value.is_empty() {
                    return Err("--explain requires a rule ID".to_string());
                }
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
            other if other.starts_with("--init-config=") => {
                let value = other
                    .split_once('=')
                    .map(|(_, v)| v)
                    .unwrap_or_default()
                    .trim();
                if value.is_empty() {
                    return Err("--init-config requires a file path when using =".to_string());
                }
                opts.init_config = Some(PathBuf::from(value));
            }
            "-B" | "--init-baseline" => {
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
            other if other.starts_with("--init-baseline=") => {
                let value = other
                    .split_once('=')
                    .map(|(_, v)| v)
                    .unwrap_or_default()
                    .trim();
                if value.is_empty() {
                    return Err("--init-baseline requires a file path when using =".to_string());
                }
                opts.init_baseline = Some(PathBuf::from(value));
            }
            "-b" | "--baseline" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a file path"))?;
                opts.baseline = Some(PathBuf::from(value));
            }
            other if other.starts_with("--baseline=") => {
                let value = other
                    .split_once('=')
                    .map(|(_, v)| v)
                    .unwrap_or_default()
                    .trim();
                if value.is_empty() {
                    return Err("--baseline requires a file path".to_string());
                }
                opts.baseline = Some(PathBuf::from(value));
            }
            "-c" | "--config" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a file path"))?;
                opts.config = Some(PathBuf::from(value));
            }
            other if other.starts_with("--config=") => {
                let value = other
                    .split_once('=')
                    .map(|(_, v)| v)
                    .unwrap_or_default()
                    .trim();
                if value.is_empty() {
                    return Err("--config requires a file path".to_string());
                }
                opts.config = Some(PathBuf::from(value));
            }
            "-r" | "--rules" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a comma-separated list of rule IDs"))?;
                merge_list(&mut opts.rule_filter, value, str::to_uppercase);
            }
            other if other.starts_with("--rules=") => {
                let value = other.split_once('=').map(|(_, v)| v).unwrap_or_default();
                merge_list(&mut opts.rule_filter, value, str::to_uppercase);
            }
            "-g" | "--categories" => {
                let value = iter.next().ok_or_else(|| {
                    format!("{arg} requires a comma-separated list of categories")
                })?;
                merge_list(&mut opts.category_filter, value, str::to_lowercase);
            }
            other if other.starts_with("--categories=") => {
                let value = other.split_once('=').map(|(_, v)| v).unwrap_or_default();
                merge_list(&mut opts.category_filter, value, str::to_lowercase);
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

fn merge_list(slot: &mut Option<Vec<String>>, value: &str, normalize: fn(&str) -> String) {
    let incoming = split_list(value, normalize);
    if incoming.is_empty() {
        return;
    }
    match slot {
        Some(existing) => {
            for item in incoming {
                if !existing.iter().any(|seen| seen == &item) {
                    existing.push(item);
                }
            }
        }
        None => *slot = Some(incoming),
    }
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
    fn rule_filter_ignores_case() {
        let args: Vec<String> = ["--rules", "fe001"].iter().map(|s| s.to_string()).collect();
        let opts = parse(&args).unwrap();
        let rules = all_rules();
        let todo = rules.iter().find(|r| r.id() == "FE001").unwrap();
        assert!(opts.allows_rule(todo.as_ref()));
    }

    #[test]
    fn parses_explain_and_init_flags() {
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

    #[test]
    fn parses_equals_value_forms() {
        let args: Vec<String> = [
            "--config=custom.toml",
            "--rules=fe001,FE004",
            "--categories=debug,unsafe",
            "--explain=fe080",
            "--baseline=base.txt",
            "--init-config=starter.toml",
            "--init-baseline=seed.baseline",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let opts = parse(&args).unwrap();
        assert_eq!(opts.config, Some(PathBuf::from("custom.toml")));
        assert_eq!(
            opts.rule_filter,
            Some(vec!["FE001".to_string(), "FE004".to_string()])
        );
        assert_eq!(
            opts.category_filter,
            Some(vec!["debug".to_string(), "unsafe".to_string()])
        );
        assert_eq!(opts.explain, Some("FE080".to_string()));
        assert_eq!(opts.baseline, Some(PathBuf::from("base.txt")));
        assert_eq!(opts.init_config, Some(PathBuf::from("starter.toml")));
        assert_eq!(opts.init_baseline, Some(PathBuf::from("seed.baseline")));
    }

    #[test]
    fn parses_benchmark_default_and_value_forms() {
        let args_default: Vec<String> = ["--benchmark", "src"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let opts_default = parse(&args_default).unwrap();
        assert_eq!(opts_default.benchmark_iterations, Some(5));

        let args_value: Vec<String> = ["--benchmark", "9", "src"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let opts_value = parse(&args_value).unwrap();
        assert_eq!(opts_value.benchmark_iterations, Some(9));

        let args_equals: Vec<String> = ["--benchmark=3", "src"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let opts_equals = parse(&args_equals).unwrap();
        assert_eq!(opts_equals.benchmark_iterations, Some(3));
    }

    #[test]
    fn parses_update_flags() {
        let args: Vec<String> = ["--check-update", "--self-update"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let opts = parse(&args).unwrap();
        assert!(opts.check_update);
        assert!(opts.self_update);
    }

    #[test]
    fn merges_repeated_filters() {
        let args: Vec<String> = [
            "--rules",
            "FE001,FE004",
            "--rules=FE004,FE080",
            "--categories",
            "debug,lint",
            "--categories=lint,secrets",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let opts = parse(&args).unwrap();
        assert_eq!(
            opts.rule_filter,
            Some(vec![
                "FE001".to_string(),
                "FE004".to_string(),
                "FE080".to_string(),
            ])
        );
        assert_eq!(
            opts.category_filter,
            Some(vec![
                "debug".to_string(),
                "lint".to_string(),
                "secrets".to_string(),
            ])
        );
    }

    #[test]
    fn parses_short_aliases() {
        let args: Vec<String> = [
            "-j",
            "-s",
            "-p",
            "-l",
            "-r",
            "FE001",
            "-g",
            "debug",
            "-x",
            "FE080",
            "-c",
            "fe203.toml",
            "-b",
            "base.txt",
            "-B",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let opts = parse(&args).unwrap();
        assert!(opts.json);
        assert!(opts.sarif);
        assert!(opts.pretty);
        assert!(opts.list_rules);
        assert_eq!(opts.rule_filter, Some(vec!["FE001".to_string()]));
        assert_eq!(opts.category_filter, Some(vec!["debug".to_string()]));
        assert_eq!(opts.explain, Some("FE080".to_string()));
        assert_eq!(opts.config, Some(PathBuf::from("fe203.toml")));
        assert_eq!(opts.baseline, Some(PathBuf::from("base.txt")));
        assert_eq!(opts.init_baseline, Some(PathBuf::from("fe203.baseline")));
    }
}
