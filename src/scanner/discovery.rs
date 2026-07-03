use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::patterns::{compile_patterns, matches_any_pattern, CompiledPattern};

pub fn expand_manifest_targets(targets: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for target in targets {
        add_target(target.clone(), &mut out, &mut seen);

        let manifest = if target.is_file() && target.file_name().is_some_and(|n| n == "Cargo.toml")
        {
            Some(target.clone())
        } else {
            let candidate = target.join("Cargo.toml");
            if candidate.is_file() {
                Some(candidate)
            } else {
                None
            }
        };

        let Some(manifest) = manifest else {
            continue;
        };
        if let Some(dir) = manifest.parent() {
            add_target(dir.to_path_buf(), &mut out, &mut seen);
            if let Ok(text) = std::fs::read_to_string(&manifest) {
                for member in parse_workspace_members(&text) {
                    add_target(dir.join(member), &mut out, &mut seen);
                }
            }
        }
    }

    out
}

pub fn discover_files(root: &Path, exclude: &[String], include: &[String], out: &mut Vec<PathBuf>) {
    let mut push = |path: PathBuf| out.push(path);
    discover_files_stream(root, exclude, include, &mut push);
}

pub fn discover_files_stream(
    root: &Path,
    exclude: &[String],
    include: &[String],
    on_file: &mut dyn FnMut(PathBuf),
) {
    if root.is_file() {
        on_file(root.to_path_buf());
        return;
    }
    let exclude = compile_patterns(exclude);
    let include = compile_patterns(include);
    walk(root, root, &exclude, &include, on_file);
}

fn add_target(path: PathBuf, out: &mut Vec<PathBuf>, seen: &mut HashSet<String>) {
    let key = path.to_string_lossy().replace('\\', "/");
    if seen.insert(key) {
        out.push(path);
    }
}

fn parse_workspace_members(manifest: &str) -> Vec<String> {
    let mut in_workspace = false;
    let mut collecting_members = false;
    let mut members_raw = String::new();

    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_workspace = line == "[workspace]";
            collecting_members = false;
            continue;
        }
        if !in_workspace || line.is_empty() || line.starts_with('#') {
            continue;
        }

        if collecting_members {
            members_raw.push_str(line);
            if line.contains(']') {
                collecting_members = false;
            }
            continue;
        }

        if line.starts_with("members") {
            let Some((_, rhs)) = line.split_once('=') else {
                continue;
            };
            let rhs = rhs.trim();
            members_raw.push_str(rhs);
            if !rhs.contains(']') {
                collecting_members = true;
            }
        }
    }

    let inner = members_raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or("");

    inner
        .split(',')
        .map(str::trim)
        .filter_map(|item| item.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn walk(
    dir: &Path,
    root: &Path,
    exclude: &[CompiledPattern],
    include: &[CompiledPattern],
    on_file: &mut dyn FnMut(PathBuf),
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();

    for path in paths {
        if matches_any_pattern(&path, root, exclude) {
            continue;
        }
        if path.is_dir() {
            walk(&path, root, exclude, include, on_file);
        } else if path.extension().is_some_and(|ext| ext == "rs")
            || matches_any_pattern(&path, root, include)
        {
            on_file(path);
        }
    }
}
