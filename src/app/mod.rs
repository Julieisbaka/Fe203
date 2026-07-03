use std::path::PathBuf;

use crate::config::Config;
use crate::rules::Rule;
use crate::{cli, reporting, rules, scanner};

mod cargo;
mod path_setup;
mod scan;

/// Runs the CLI with the given arguments. Returns the process exit code:
/// `0` = clean, `1` = findings reported, `2` = usage/config error.
pub fn run(args: &[String]) -> i32 {
    let opts = match cli::parse(args) {
        Ok(opts) => opts,
        Err(err) => {
            eprintln!("error: {err}");
            eprintln!("{}", cli::usage_text());
            return 2;
        }
    };

    path_setup::ensure_exe_dir_in_path();

    if should_show_intro(args) {
        println!("{}", cli::intro_text());
        return 0;
    }

    if opts.help {
        println!("{}", cli::usage_text());
        return 0;
    }
    if opts.version {
        println!("fe203 {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }

    if opts.json && opts.sarif {
        eprintln!("error: --json and --sarif cannot be used together");
        return 2;
    }
    if opts.pretty && !opts.json && !opts.sarif {
        eprintln!("error: --pretty requires --json or --sarif");
        return 2;
    }
    if opts.baseline.is_some() && opts.init_baseline.is_some() {
        eprintln!("error: --baseline and --init-baseline cannot be used together");
        return 2;
    }

    let registry = rules::all_rules();
    let show_progress = progress_enabled(&opts);

    if let Some(path) = &opts.init_config {
        let template = Config::template_from_workspace(
            &std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        );
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
        .filter(|rule| {
            if opts.max {
                true
            } else {
                config.rule_enabled(*rule) && opts.allows_rule(*rule)
            }
        })
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
    let targets = scanner::expand_manifest_targets(&targets);
    let cargo_targets = cargo::cargo_target_dirs(&targets);

    if opts.check_syntax || opts.max {
        let source = if opts.max { "--max" } else { "--check-syntax" };
        if let Err(err) = cargo::run_syntax_checks(&cargo_targets, source) {
            eprintln!("error: {err}");
            return 2;
        }
    }
    if opts.max {
        if let Err(err) = cargo::run_cargo_tests(&cargo_targets) {
            eprintln!("error: {err}");
            return 2;
        }
    }

    let mut scan_outcome =
        match scan::execute_scan(&targets, &config, &enabled, show_progress, !opts.max) {
            Ok(outcome) => outcome,
            Err(err) => {
                eprintln!("error: {err}");
                return 2;
            }
        };

    reporting::apply_severity_overrides(&mut scan_outcome.findings, &config);

    if let Some(path) = &opts.init_baseline {
        if path.exists() {
            eprintln!("error: baseline target already exists: {}", path.display());
            return 2;
        }
        let mut lines = Vec::new();
        lines.push("# fe203 baseline v1".to_string());
        lines.extend(reporting::baseline_lines(&scan_outcome.findings));
        if let Err(err) = std::fs::write(path, lines.join("\n")) {
            eprintln!("error: cannot write baseline {}: {err}", path.display());
            return 2;
        }
        println!("generated {}", path.display());
        return 0;
    }

    if let Some(path) = &opts.baseline {
        let baseline_text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) => {
                eprintln!("error: cannot read baseline {}: {err}", path.display());
                return 2;
            }
        };
        scan_outcome.findings = reporting::apply_baseline(&scan_outcome.findings, &baseline_text);
    }

    if opts.sarif {
        if opts.pretty {
            println!("{}", reporting::render_sarif_pretty(&scan_outcome.findings));
        } else {
            println!("{}", reporting::render_sarif(&scan_outcome.findings));
        }
    } else if opts.json {
        if opts.pretty {
            println!("{}", reporting::render_json_pretty(&scan_outcome.findings));
        } else {
            println!("{}", reporting::render_json(&scan_outcome.findings));
        }
    } else {
        print!(
            "{}",
            reporting::render_human(
                &scan_outcome.findings,
                scan_outcome.files_scanned,
                enabled.len()
            )
        );
    }

    if scan_outcome.findings.is_empty() {
        0
    } else {
        1
    }
}

fn should_show_intro(args: &[String]) -> bool {
    args.is_empty()
}

fn progress_enabled(opts: &cli::CliOptions) -> bool {
    !opts.json && !opts.sarif && std::env::var("FE203_NO_PROGRESS").is_err()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shows_intro_for_empty_args() {
        let no_args: Vec<String> = vec![];
        let with_path = vec!["src".to_string()];
        let with_flag = vec!["--help".to_string()];

        assert!(should_show_intro(&no_args));
        assert!(!should_show_intro(&with_path));
        assert!(!should_show_intro(&with_flag));
    }
}
