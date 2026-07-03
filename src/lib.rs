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
            eprintln!("{}", cli::usage_text());
            return 2;
        }
    };

    maybe_register_exe_dir_in_user_path();

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
        if opts.pretty {
            println!("{}", reporting::render_sarif_pretty(&findings));
        } else {
            println!("{}", reporting::render_sarif(&findings));
        }
    } else if opts.json {
        if opts.pretty {
            println!("{}", reporting::render_json_pretty(&findings));
        } else {
            println!("{}", reporting::render_json(&findings));
        }
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

fn should_show_intro(args: &[String]) -> bool {
    args.is_empty()
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

fn maybe_register_exe_dir_in_user_path() {
    #[cfg(not(windows))]
    {
        return;
    }

    #[cfg(windows)]
    {
        if auto_path_disabled() {
            return;
        }

        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let Some(dir) = exe.parent() else {
            return;
        };
        let dir_str = dir.to_string_lossy().to_string();

        if process_path_contains_dir(&dir_str) {
            return;
        }

        match update_user_path_with_powershell(&dir_str) {
            Some(true) => {
                append_to_process_path(&dir_str);
                eprintln!(
                    "info: added {} to your user PATH; open a new terminal to use fe203 globally",
                    dir.display()
                );
            }
            Some(false) => {}
            None => {
                eprintln!(
                    "warning: could not update user PATH automatically; add {} to your PATH manually",
                    dir.display()
                );
            }
        }
    }
}

fn auto_path_disabled() -> bool {
    std::env::var("FE203_NO_AUTO_PATH")
        .map(|v| {
            let lower = v.trim().to_ascii_lowercase();
            lower == "1" || lower == "true" || lower == "yes"
        })
        .unwrap_or(false)
}

#[cfg(windows)]
fn process_path_contains_dir(dir: &str) -> bool {
    let target = dir.trim_end_matches(['\\', '/']).to_ascii_lowercase();
    std::env::var("PATH")
        .ok()
        .map(|path| {
            path.split(';').any(|entry| {
                entry
                    .trim()
                    .trim_end_matches(['\\', '/'])
                    .eq_ignore_ascii_case(&target)
            })
        })
        .unwrap_or(false)
}

#[cfg(windows)]
fn append_to_process_path(dir: &str) {
    if process_path_contains_dir(dir) {
        return;
    }
    let existing = std::env::var("PATH").unwrap_or_default();
    let new_path = if existing.trim().is_empty() {
        dir.to_string()
    } else {
        format!("{};{}", existing.trim_end_matches(';'), dir)
    };
    // SAFETY: this process intentionally updates its own PATH environment variable.
    unsafe {
        std::env::set_var("PATH", new_path);
    }
}

#[cfg(windows)]
fn update_user_path_with_powershell(dir: &str) -> Option<bool> {
    let escaped = ps_single_quote_escape(dir);
    let script = format!(
        "$d='{escaped}';$p=[Environment]::GetEnvironmentVariable('Path','User');$parts=@();if($p){{$parts=$p -split ';' | ForEach-Object {{$_.Trim().TrimEnd('\\')}} | Where-Object {{$_}}}};$dn=$d.TrimEnd('\\');if($parts -contains $dn){{exit 10}};$n=if([string]::IsNullOrWhiteSpace($p)){{$d}}else{{$p.TrimEnd(';')+';'+$d}};[Environment]::SetEnvironmentVariable('Path',$n,'User');"
    );

    let status = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .status()
        .ok()?;

    let code = status.code().unwrap_or(1);
    if code == 0 {
        Some(true)
    } else if code == 10 {
        Some(false)
    } else {
        None
    }
}

#[cfg(windows)]
fn ps_single_quote_escape(input: &str) -> String {
    input.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shows_intro_only_for_empty_args() {
        let no_args: Vec<String> = vec![];
        let with_path = vec!["src".to_string()];
        let with_flag = vec!["--help".to_string()];

        assert!(should_show_intro(&no_args));
        assert!(!should_show_intro(&with_path));
        assert!(!should_show_intro(&with_flag));
    }

    #[test]
    fn auto_path_disable_values_are_recognized() {
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::set_var("FE203_NO_AUTO_PATH", "1");
        }
        assert!(auto_path_disabled());
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::set_var("FE203_NO_AUTO_PATH", "true");
        }
        assert!(auto_path_disabled());
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::remove_var("FE203_NO_AUTO_PATH");
        }
        assert!(!auto_path_disabled());
    }

    #[cfg(windows)]
    #[test]
    fn process_path_contains_dir_matches_case_insensitive_and_trailing_slash() {
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::set_var("PATH", r"C:\Tools\Fe203;C:\Other");
        }
        assert!(process_path_contains_dir(r"c:\tools\fe203\"));
        assert!(!process_path_contains_dir(r"c:\missing"));
    }
}
