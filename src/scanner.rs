//! File discovery and scan orchestration.
// fe203-ignore-file FE001, FE020

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::finding::Finding;
use crate::rules::{FileContext, Rule};

/// Expands scan targets with manifest-aware Cargo workspace discovery.
///
/// If a target is a directory containing `Cargo.toml` or a `Cargo.toml` file,
/// Fe203 discovers `[workspace].members` and adds each member path to the
/// target set.
pub fn expand_manifest_targets(targets: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for target in targets {
        add_target(target.clone(), &mut out, &mut seen);

        let manifest = if target.is_file() && target.file_name().is_some_and(|n| n == "Cargo.toml") {
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

/// Recursively collects `.rs` files under `root` into `out`, skipping any
/// directory or file whose name matches an `exclude` entry. If `root` is a
/// file it is added directly (regardless of extension) so users can scan
/// arbitrary files explicitly.
pub fn discover_files(root: &Path, exclude: &[String], include: &[String], out: &mut Vec<PathBuf>) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    walk(root, root, exclude, include, out);
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

fn walk(dir: &Path, root: &Path, exclude: &[String], include: &[String], out: &mut Vec<PathBuf>) {
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
            walk(&path, root, exclude, include, out);
        } else if path.extension().is_some_and(|ext| ext == "rs")
            || matches_any_pattern(&path, root, include)
        {
            out.push(path);
        }
    }
}

/// Runs every enabled rule over every file and collects the findings,
/// ordered by file, then line, then rule ID.
pub fn scan_files(files: &[PathBuf], rules: &[&dyn Rule]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in files {
        let Ok(content) = std::fs::read_to_string(file) else {
            eprintln!("warning: skipping unreadable file {}", file.display());
            continue;
        };
        let ctx = FileContext::new(file, &content);
        for rule in rules {
            findings.extend(rule.scan(&ctx));
        }
    }
    findings.sort_by(|a, b| {
        (&a.file, a.line, a.column, a.rule_id).cmp(&(&b.file, b.line, b.column, b.rule_id))
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::all_rules;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fe203-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn discovers_only_rust_files_and_honors_excludes() {
        let dir = temp_dir("discover");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::create_dir_all(dir.join("target")).unwrap();
        std::fs::write(dir.join("src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(dir.join("src/notes.txt"), "not rust\n").unwrap();
        std::fs::write(dir.join("target/gen.rs"), "fn skipped() {}\n").unwrap();

        let mut files = Vec::new();
        discover_files(&dir, &["target".to_string()], &[], &mut files);

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("src/main.rs") || files[0].ends_with("src\\main.rs"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expands_workspace_member_targets() {
        let dir = temp_dir("workspace-members");
        std::fs::create_dir_all(dir.join("crates/a/src")).unwrap();
        std::fs::create_dir_all(dir.join("crates/b/src")).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/a\", \"crates/b\"]\n",
        )
        .unwrap();

        let targets = expand_manifest_targets(&[dir.clone()]);
        assert!(targets.iter().any(|p| p.ends_with("crates/a") || p.ends_with("crates\\a")));
        assert!(targets.iter().any(|p| p.ends_with("crates/b") || p.ends_with("crates\\b")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_reports_expected_rules() {
        let dir = temp_dir("scan");
        std::fs::write(
            dir.join("bad.rs"),
            "fn f() {\n    todo!();\n    unsafe { x() }\n}\nlet password = \"hunter2\";\n",
        )
        .unwrap();

        let registry = all_rules();
        let rules: Vec<&dyn Rule> = registry.iter().map(|r| r.as_ref()).collect();
        let mut files = Vec::new();
        discover_files(&dir, &[], &[], &mut files);
        let findings = scan_files(&files, &rules);

        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        let mut ids = ids;
        ids.sort();
        assert_eq!(ids, ["FE001", "FE020", "FE040", "FE063"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discovers_included_project_files() {
        let dir = temp_dir("include");
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        std::fs::write(dir.join("build.rs"), "fn main() {}\n").unwrap();

        let mut files = Vec::new();
        discover_files(&dir, &[], &["Cargo.toml".to_string()], &mut files);

        assert!(files
            .iter()
            .any(|path| path.ends_with("Cargo.toml") || path.ends_with("Cargo.toml")));
        assert!(files
            .iter()
            .any(|path| path.ends_with("build.rs") || path.ends_with("build.rs")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn glob_patterns_match_common_gitignore_entries() {
        let dir = temp_dir("glob");
        std::fs::create_dir_all(dir.join("nested/debug")).unwrap();
        std::fs::write(dir.join("nested/debug/file.pdb"), "x").unwrap();
        std::fs::write(dir.join("nested/debug/cache.rs.bk"), "x").unwrap();

        let mut files = Vec::new();
        discover_files(
            &dir,
            &[
                "debug".to_string(),
                "*.pdb".to_string(),
                "**/*.rs.bk".to_string(),
            ],
            &[],
            &mut files,
        );
        assert!(files.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn does_not_match_partial_directory_names() {
        let dir = temp_dir("partial");
        std::fs::create_dir_all(dir.join("mytarget")).unwrap();
        std::fs::write(dir.join("mytarget/keep.rs"), "fn keep() {}\n").unwrap();

        let mut files = Vec::new();
        discover_files(&dir, &["target".to_string()], &[], &mut files);

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("mytarget/keep.rs") || files[0].ends_with("mytarget\\keep.rs"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

fn matches_any_pattern(path: &Path, root: &Path, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| matches_pattern(path, root, pattern))
}

fn matches_pattern(path: &Path, root: &Path, pattern: &str) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let basename = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    let cleaned = pattern
        .trim()
        .trim_start_matches("./")
        .trim_end_matches('/');
    if cleaned.is_empty() {
        return false;
    }
    if !cleaned.contains('*') && !cleaned.contains('?') && !cleaned.contains('/') {
        return normalized.split('/').any(|part| part == cleaned) || basename == cleaned;
    }
    if !cleaned.contains('/') {
        return glob_match_segment(cleaned, &basename);
    }
    // Slash-containing patterns are resolved relative to the scan root first
    // (standard gitignore-like semantics), falling back to matching against
    // the full path for backward compatibility.
    if let Some(relative) = path
        .strip_prefix(root)
        .ok()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
    {
        if relative == cleaned
            || relative.ends_with(&format!("/{cleaned}"))
            || glob_match_path(cleaned, &relative)
        {
            return true;
        }
    }
    normalized == cleaned
        || normalized.ends_with(&format!("/{cleaned}"))
        || glob_match_path(cleaned, &normalized)
}

fn glob_match_segment(pattern: &str, text: &str) -> bool {
    let pattern_bytes = pattern.as_bytes();
    let text_bytes = text.as_bytes();
    let mut pattern_index = 0;
    let mut text_index = 0;
    let mut star_index = None;
    let mut text_after_star = 0;

    while text_index < text_bytes.len() {
        if pattern_index < pattern_bytes.len()
            && pattern_bytes[pattern_index] != b'*'
            && pattern_bytes[pattern_index] != b'?'
            && pattern_bytes[pattern_index] == text_bytes[text_index]
        {
            pattern_index += 1;
            text_index += 1;
        } else if pattern_index < pattern_bytes.len() && pattern_bytes[pattern_index] == b'?' {
            if text_bytes[text_index] == b'/' {
                return false;
            }
            pattern_index += 1;
            text_index += 1;
        } else if pattern_index < pattern_bytes.len() && pattern_bytes[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            text_after_star = text_index;
        } else if let Some(star) = star_index {
            if text_bytes[text_after_star] == b'/' {
                return false;
            }
            text_after_star += 1;
            text_index = text_after_star;
            pattern_index = star + 1;
        } else {
            return false;
        }
    }

    while pattern_index < pattern_bytes.len() && pattern_bytes[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern_bytes.len()
}

fn glob_match_path(pattern: &str, text: &str) -> bool {
    let pattern_segments: Vec<&str> = pattern
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let text_segments: Vec<&str> = text
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let mut memo = vec![vec![None; text_segments.len() + 1]; pattern_segments.len() + 1];

    fn inner(
        pattern_segments: &[&str],
        text_segments: &[&str],
        pattern_index: usize,
        text_index: usize,
        memo: &mut [Vec<Option<bool>>],
    ) -> bool {
        if let Some(result) = memo[pattern_index][text_index] {
            return result;
        }

        let result = if pattern_index == pattern_segments.len() {
            text_index == text_segments.len()
        } else if pattern_segments[pattern_index] == "**" {
            inner(
                pattern_segments,
                text_segments,
                pattern_index + 1,
                text_index,
                memo,
            ) || (text_index < text_segments.len()
                && inner(
                    pattern_segments,
                    text_segments,
                    pattern_index,
                    text_index + 1,
                    memo,
                ))
        } else if text_index < text_segments.len()
            && glob_match_segment(pattern_segments[pattern_index], text_segments[text_index])
        {
            inner(
                pattern_segments,
                text_segments,
                pattern_index + 1,
                text_index + 1,
                memo,
            )
        } else {
            false
        };

        memo[pattern_index][text_index] = Some(result);
        result
    }

    inner(&pattern_segments, &text_segments, 0, 0, &mut memo)
}
