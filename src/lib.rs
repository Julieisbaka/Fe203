//! Fe203 — a fast, modular scanner and linter for Rust code.

pub mod cli;
pub mod config;
pub mod finding;
pub mod reporting;
pub mod rules;
pub mod scanner;

use std::path::PathBuf;
use std::process::Command;

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

    if opts.json && opts.sarif {
        eprintln!("error: --json and --sarif cannot be used together");
        return 2;
    }
    if opts.baseline.is_some() && opts.init_baseline.is_some() {
        eprintln!("error: --baseline and --init-baseline cannot be used together");
        return 2;
    }

    let registry = rules::all_rules();

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
    let cargo_targets = cargo_target_dirs(&targets);

    if opts.check_syntax || opts.max {
        let source = if opts.max { "--max" } else { "--check-syntax" };
        if let Err(err) = run_syntax_checks(&cargo_targets, source) {
            eprintln!("error: {err}");
            return 2;
        }
    }
    if opts.max {
        if let Err(err) = run_cargo_tests(&cargo_targets) {
            eprintln!("error: {err}");
            return 2;
        }
    }

    let mut files = Vec::new();
    for target in &targets {
        if !target.exists() {
            eprintln!("error: path does not exist: {}", target.display());
            return 2;
        }
        scanner::discover_files(target, &config.exclude, &config.include, &mut files);
    }

    let mut findings = scanner::scan_files(&files, &enabled);
    reporting::apply_severity_overrides(&mut findings, &config);

    if let Some(path) = &opts.init_baseline {
        if path.exists() {
            eprintln!("error: baseline target already exists: {}", path.display());
            return 2;
        }
        let mut lines = Vec::new();
        lines.push("# fe203 baseline v1".to_string());
        lines.extend(reporting::baseline_lines(&findings));
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
        findings = reporting::apply_baseline(&findings, &baseline_text);
    }

    if opts.sarif {
        println!("{}", reporting::render_sarif(&findings));
    } else if opts.json {
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

fn cargo_target_dirs(targets: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for target in targets {
        let maybe_dir = if target.is_file() {
            if target.file_name().is_some_and(|name| name == "Cargo.toml") {
                target.parent().map(|dir| dir.to_path_buf())
            } else {
                target.parent().and_then(|dir| {
                    if dir.join("Cargo.toml").is_file() {
                        Some(dir.to_path_buf())
                    } else {
                        None
                    }
                })
            }
        } else if target.join("Cargo.toml").is_file() {
            Some(target.to_path_buf())
        } else {
            None
        };
        if let Some(dir) = maybe_dir {
            let key = dir.to_string_lossy().replace('\\', "/");
            if seen.insert(key) {
                out.push(dir);
            }
        }
    }
    out
}

fn run_syntax_checks(check_dirs: &[PathBuf], source: &str) -> Result<(), String> {
    if check_dirs.is_empty() {
        eprintln!(
            "warning: {source} found no Cargo.toml in scan targets; skipping syntax checks"
        );
        return Ok(());
    }

    for dir in check_dirs {
        let status = Command::new("cargo")
            .arg("check")
            .arg("--quiet")
            .current_dir(&dir)
            .status()
            .map_err(|err| format!("failed to run cargo check in {}: {err}", dir.display()))?;
        if !status.success() {
            return Err(format!("cargo check failed in {}", dir.display()));
        }
    }

    Ok(())
}

fn run_cargo_tests(check_dirs: &[PathBuf]) -> Result<(), String> {
    if check_dirs.is_empty() {
        eprintln!("warning: --max found no Cargo.toml in scan targets; skipping cargo test");
        return Ok(());
    }

    for dir in check_dirs {
        let status = Command::new("cargo")
            .arg("test")
            .arg("--quiet")
            .current_dir(dir)
            .status()
            .map_err(|err| format!("failed to run cargo test in {}: {err}", dir.display()))?;
        if !status.success() {
            return Err(format!("cargo test failed in {}", dir.display()));
        }
    }

    Ok(())
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
