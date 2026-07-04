use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::rules::Rule;
use crate::{cli, reporting, rules, scanner};

mod cargo;
mod path_setup;
mod scan;
mod update;

const DEFAULT_BENCHMARK_TARGET: &str = "benchmarks/workload";

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

    if opts.check_update && opts.self_update {
        eprintln!("error: --check-update and --self-update cannot be used together");
        return 2;
    }
    if opts.check_update {
        return update::run_check_update(env!("CARGO_PKG_VERSION"));
    }
    if opts.self_update {
        return update::run_self_update(env!("CARGO_PKG_VERSION"));
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

    path_setup::ensure_exe_dir_in_path();

    if let Some(iterations) = opts.benchmark_iterations {
        return run_benchmark_mode(args, iterations);
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

fn run_benchmark_mode(args: &[String], iterations: usize) -> i32 {
    let mut benchmark_args = strip_benchmark_args(args);
    if !benchmark_args.iter().any(|arg| !arg.starts_with('-')) {
        benchmark_args.push(DEFAULT_BENCHMARK_TARGET.to_string());
    }
    let target = benchmark_args
        .iter()
        .find(|arg| !arg.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| DEFAULT_BENCHMARK_TARGET.to_string());

    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("error: cannot resolve current executable path: {err}");
            return 2;
        }
    };

    println!("fe203 benchmark mode");
    println!("target: {target}");
    println!("iterations: {iterations}");

    let mut times = Vec::with_capacity(iterations);
    for idx in 0..iterations {
        let start = Instant::now();
        let status = match Command::new(&exe)
            .args(&benchmark_args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) => status,
            Err(err) => {
                eprintln!(
                    "error: benchmark iteration {} failed to start: {err}",
                    idx + 1
                );
                return 2;
            }
        };

        if !status.success() && status.code() != Some(1) {
            eprintln!(
                "error: benchmark iteration {} failed with exit code {:?}",
                idx + 1,
                status.code()
            );
            return 2;
        }

        let elapsed = start.elapsed();
        times.push(elapsed);
        println!("run {:>2}: {}", idx + 1, format_benchmark_duration(elapsed));
    }

    let summary = summarize_times(&times);
    println!("\nsummary");
    println!("min:    {}", format_benchmark_duration(summary.min));
    println!("max:    {}", format_benchmark_duration(summary.max));
    println!("mean:   {}", format_benchmark_duration(summary.mean));
    println!("median: {}", format_benchmark_duration(summary.median));
    0
}

fn strip_benchmark_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut idx = 0usize;

    while idx < args.len() {
        let arg = &args[idx];
        if arg == "--benchmark" {
            idx += 1;
            if idx < args.len()
                && !args[idx].starts_with('-')
                && args[idx].parse::<usize>().ok().is_some_and(|v| v > 0)
            {
                idx += 1;
            }
            continue;
        }
        if arg.starts_with("--benchmark=") {
            idx += 1;
            continue;
        }

        out.push(arg.clone());
        idx += 1;
    }

    out
}

struct BenchmarkStats {
    min: Duration,
    max: Duration,
    mean: Duration,
    median: Duration,
}

fn summarize_times(times: &[Duration]) -> BenchmarkStats {
    let mut sorted = times.to_vec();
    sorted.sort();

    let min = *sorted.first().unwrap_or(&Duration::from_millis(0));
    let max = *sorted.last().unwrap_or(&Duration::from_millis(0));
    let total_secs: f64 = sorted.iter().map(Duration::as_secs_f64).sum();
    let mean = if sorted.is_empty() {
        Duration::from_millis(0)
    } else {
        Duration::from_secs_f64(total_secs / sorted.len() as f64)
    };
    let median = if sorted.is_empty() {
        Duration::from_millis(0)
    } else {
        sorted[sorted.len() / 2]
    };

    BenchmarkStats {
        min,
        max,
        mean,
        median,
    }
}

fn format_benchmark_duration(value: Duration) -> String {
    format!("{:.2}ms", value.as_secs_f64() * 1000.0)
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

    #[test]
    fn strips_benchmark_args() {
        let args = vec![
            "--benchmark".to_string(),
            "7".to_string(),
            "src".to_string(),
            "--json".to_string(),
        ];
        assert_eq!(strip_benchmark_args(&args), vec!["src", "--json"]);

        let args_equals = vec!["--benchmark=3".to_string(), "src".to_string()];
        assert_eq!(strip_benchmark_args(&args_equals), vec!["src"]);
    }

    #[test]
    fn benchmark_mode_defaults_target_folder() {
        let args = vec!["--benchmark".to_string()];
        let mut stripped = strip_benchmark_args(&args);
        if !stripped.iter().any(|arg| !arg.starts_with('-')) {
            stripped.push(DEFAULT_BENCHMARK_TARGET.to_string());
        }
        assert_eq!(stripped, vec![DEFAULT_BENCHMARK_TARGET.to_string()]);
    }
}
