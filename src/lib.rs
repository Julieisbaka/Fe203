//! Fe203 — a fast, modular scanner and linter for Rust code.

pub mod cli;
pub mod config;
pub mod finding;
pub mod reporting;
pub mod rules;
pub mod scanner;

use std::path::PathBuf;

use config::Config;
use rules::Rule;

/// Runs the CLI with the given arguments. Returns the process exit code:
/// `0` = clean, `1` = findings reported, `2` = usage/config error.
pub fn run(args: &[String]) -> i32 {
    let opts = match cli::parse(args) {
        Ok(opts) => opts,
        Err(err) => {
            eprintln!("error: {err}");
            eprintln!("{}", cli::USAGE);
            return 2;
        }
    };

    if opts.help {
        println!("{}", cli::USAGE);
        return 0;
    }
    if opts.version {
        println!("fe203 {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }

    let registry = rules::all_rules();

    if let Some(path) = &opts.init_config {
        let template = Config::template_from_workspace(&std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        if path.exists() {
            eprintln!("error: template target already exists: {}", path.display());
            return 2;
        }
        if let Err(err) = std::fs::write(path, template) {
            eprintln!("error: cannot write template {}: {err}", path.display());
            return 2;
        }
        println!("generated {}", path.display());
        return 0;
    }

    if let Some(rule_id) = &opts.explain {
        if let Some(rule) = rules::rule_by_id(&registry, rule_id) {
            print!("{}", rules::render_rule_explanation(rule));
            return 0;
        }
        eprintln!("error: unknown rule ID: {rule_id}");
        return 2;
    }

    if opts.list_rules {
        print!("{}", rules::render_rule_index(&registry));
        return 0;
    }

    let config = match load_config(&opts) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {err}");
            return 2;
        }
    };

    let enabled: Vec<&dyn Rule> = registry
        .iter()
        .map(|rule| rule.as_ref())
        .filter(|rule| config.rule_enabled(*rule))
        .filter(|rule| opts.allows_rule(*rule))
        .collect();

    if enabled.is_empty() {
        eprintln!("warning: no rules are enabled; nothing to do");
        return 0;
    }

    let targets: Vec<PathBuf> = if opts.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        opts.paths.clone()
    };

    let mut files = Vec::new();
    for target in &targets {
        if !target.exists() {
            eprintln!("error: path does not exist: {}", target.display());
            return 2;
        }
        scanner::discover_files(target, &config.exclude, &config.include, &mut files);
    }

    let findings = scanner::scan_files(&files, &enabled);

    if opts.json {
        println!("{}", reporting::render_json(&findings));
    } else {
        print!(
            "{}",
            reporting::render_human(&findings, files.len(), enabled.len())
        );
    }

    if findings.is_empty() {
        0
    } else {
        1
    }
}

fn load_config(opts: &cli::CliOptions) -> Result<Config, String> {
    match &opts.config {
        Some(path) => Config::load(path),
        None => {
            let default_path = PathBuf::from("fe203.toml");
            if default_path.is_file() {
                Config::load(&default_path)
            } else {
                Ok(Config::default())
            }
        }
    }
}
