use std::path::PathBuf;
use std::process::Command;

pub(super) fn cargo_target_dirs(targets: &[PathBuf]) -> Vec<PathBuf> {
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

pub(super) fn run_syntax_checks(check_dirs: &[PathBuf], source: &str) -> Result<(), String> {
    if check_dirs.is_empty() {
        eprintln!("warning: {source} found no Cargo.toml in scan targets; skipping syntax checks");
        return Ok(());
    }

    for dir in check_dirs {
        let status = Command::new("cargo")
            .arg("check")
            .arg("--quiet")
            .current_dir(dir)
            .status()
            .map_err(|err| format!("failed to run cargo check in {}: {err}", dir.display()))?;
        if !status.success() {
            return Err(format!("cargo check failed in {}", dir.display()));
        }
    }

    Ok(())
}

pub(super) fn run_cargo_tests(check_dirs: &[PathBuf]) -> Result<(), String> {
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
