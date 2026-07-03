//! File discovery and scan orchestration.
// fe203-ignore-file FE001, FE020

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;

use crate::finding::Finding;
use crate::rules::lint::suppressions::dead_suppression_findings;
use crate::rules::{FileContext, Rule};

pub struct ScanCacheOptions<'a> {
    pub fingerprint: &'a str,
    pub cache_file: &'a Path,
}

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

/// Recursively collects `.rs` files under `root` into `out`, skipping any
/// directory or file whose name matches an `exclude` entry. If `root` is a
/// file it is added directly (regardless of extension) so users can scan
/// arbitrary files explicitly.
pub fn discover_files(root: &Path, exclude: &[String], include: &[String], out: &mut Vec<PathBuf>) {
    let mut push = |path: PathBuf| out.push(path);
    discover_files_stream(root, exclude, include, &mut push);
}

/// Recursively discovers scan files and invokes `on_file` for each matching
/// path as it is found.
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

/// Runs every enabled rule over every file and collects the findings,
/// ordered by file, then line, then rule ID.
pub fn scan_files(files: &[PathBuf], rules: &[&dyn Rule], use_prefilter: bool) -> Vec<Finding> {
    scan_files_with_cache(files, rules, use_prefilter, None)
}

pub fn scan_files_with_cache(
    files: &[PathBuf],
    rules: &[&dyn Rule],
    use_prefilter: bool,
    cache: Option<ScanCacheOptions<'_>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rule_map: HashMap<&'static str, &dyn Rule> =
        rules.iter().map(|rule| (rule.id(), *rule)).collect();
    let mut cache_state = cache.map(|opts| ScanCache::load(opts.cache_file, opts.fingerprint));
    let mut pending = Vec::new();

    for file in files {
        let Ok(content) = std::fs::read_to_string(file) else {
            eprintln!("warning: skipping unreadable file {}", file.display());
            continue;
        };
        let file_hash = hash_content(&content);

        if let Some(state) = &cache_state {
            if let Some(cached) = state.lookup(file, file_hash) {
                findings.extend(cached.into_iter().filter_map(|entry| {
                    let rule = rule_map.get(entry.rule_id.as_str())?;
                    Some(Finding {
                        rule_id: rule.id(),
                        rule_name: rule.name(),
                        category: rule.category(),
                        severity: rule.severity(),
                        file: file.clone(),
                        line: entry.line,
                        column: entry.column,
                        message: entry.message,
                        snippet: entry.snippet,
                        suggestion: entry.suggestion,
                        suggestion_example: entry.suggestion_example,
                    })
                }));
                continue;
            }
        }

        pending.push(PendingFile {
            file: file.clone(),
            content,
            hash: file_hash,
        });
    }

    let scanned = scan_pending_files(&pending, rules, use_prefilter);
    for scanned_file in scanned {
        if let Some(state) = &mut cache_state {
            state.store(&scanned_file.file, scanned_file.hash, &scanned_file.findings);
        }
        findings.extend(scanned_file.findings);
    }

    if let Some(state) = &mut cache_state {
        state.save();
    }

    findings.sort_by(|a, b| {
        (&a.file, a.line, a.column, a.rule_id).cmp(&(&b.file, b.line, b.column, b.rule_id))
    });
    findings
}

#[derive(Debug)]
struct PendingFile {
    file: PathBuf,
    content: String,
    hash: u64,
}

#[derive(Debug)]
struct ScannedFile {
    file: PathBuf,
    hash: u64,
    findings: Vec<Finding>,
}

fn scan_pending_files(
    pending: &[PendingFile],
    rules: &[&dyn Rule],
    use_prefilter: bool,
) -> Vec<ScannedFile> {
    if pending.is_empty() {
        return Vec::new();
    }

    let worker_count = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(pending.len())
        .max(1);

    if worker_count == 1 {
        return pending
            .iter()
            .map(|item| ScannedFile {
                file: item.file.clone(),
                hash: item.hash,
                findings: scan_single_file(&item.file, &item.content, rules, use_prefilter),
            })
            .collect();
    }

    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::with_capacity(pending.len()));
    thread::scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|| loop {
                let idx = next.fetch_add(1, Ordering::Relaxed);
                if idx >= pending.len() {
                    break;
                }
                let item = &pending[idx];
                let findings = scan_single_file(&item.file, &item.content, rules, use_prefilter);
                if let Ok(mut guard) = results.lock() {
                    guard.push(ScannedFile {
                        file: item.file.clone(),
                        hash: item.hash,
                        findings,
                    });
                }
            });
        }
    });

    let mut out = results.into_inner().unwrap_or_default();
    out.sort_by(|a, b| a.file.cmp(&b.file));
    out
}

fn scan_single_file(file: &Path, content: &str, rules: &[&dyn Rule], use_prefilter: bool) -> Vec<Finding> {
    let ctx = FileContext::new(file, content);
    let mut file_findings = Vec::new();
    let mut dead_suppression_rule = None;

    for rule in rules {
        if rule.id() == "FE066" {
            dead_suppression_rule = Some(*rule);
            continue;
        }
        if use_prefilter && !rule.should_scan(&ctx) {
            continue;
        }
        file_findings.extend(rule.scan(&ctx));
    }

    if let Some(rule) = dead_suppression_rule {
        let active_ids = file_findings
            .iter()
            .map(|finding| finding.rule_id)
            .collect::<HashSet<_>>();
        let mut dead = dead_suppression_findings(&ctx, &active_ids);
        if use_prefilter && !rule.should_scan(&ctx) {
            dead.clear();
        }
        file_findings.extend(dead);
    }

    file_findings
}

#[derive(Debug, Clone)]
struct CachedFinding {
    rule_id: String,
    line: usize,
    column: usize,
    message: String,
    snippet: String,
    suggestion: Option<String>,
    suggestion_example: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedFile {
    hash: u64,
    findings: Vec<CachedFinding>,
}

struct ScanCache {
    cache_file: PathBuf,
    fingerprint: String,
    entries: HashMap<String, CachedFile>,
    dirty: bool,
}

impl ScanCache {
    fn load(cache_file: &Path, fingerprint: &str) -> Self {
        let mut entries = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(cache_file) {
            let mut lines = text.lines();
            if let Some(header) = lines.next() {
                let expected = format!("v1|{}", escape_field(fingerprint));
                if header == expected {
                    for line in lines {
                        let parts = split_fields(line);
                        if parts.is_empty() {
                            continue;
                        }
                        if parts[0] == "F" && parts.len() == 3 {
                            if let Ok(hash) = parts[2].parse::<u64>() {
                                entries.entry(parts[1].to_string()).or_insert(CachedFile {
                                    hash,
                                    findings: Vec::new(),
                                });
                            }
                        } else if parts[0] == "R" && parts.len() == 9 {
                            if let Some(file) = entries.get_mut(parts[1]) {
                                file.findings.push(CachedFinding {
                                    rule_id: parts[2].to_string(),
                                    line: parts[3].parse::<usize>().unwrap_or(0),
                                    column: parts[4].parse::<usize>().unwrap_or(0),
                                    message: unescape_field(parts[5]),
                                    snippet: unescape_field(parts[6]),
                                    suggestion: decode_optional(parts[7]),
                                    suggestion_example: decode_optional(parts[8]),
                                });
                            }
                        }
                    }
                }
            }
        }

        ScanCache {
            cache_file: cache_file.to_path_buf(),
            fingerprint: escape_field(fingerprint),
            entries,
            dirty: false,
        }
    }

    fn lookup(&self, file: &Path, hash: u64) -> Option<Vec<CachedFinding>> {
        let key = normalize_path(file);
        let cached = self.entries.get(&key)?;
        if cached.hash != hash {
            return None;
        }
        Some(cached.findings.clone())
    }

    fn store(&mut self, file: &Path, hash: u64, findings: &[Finding]) {
        let key = normalize_path(file);
        let cached_findings = findings
            .iter()
            .map(|finding| CachedFinding {
                rule_id: finding.rule_id.to_string(),
                line: finding.line,
                column: finding.column,
                message: finding.message.clone(),
                snippet: finding.snippet.clone(),
                suggestion: finding.suggestion.clone(),
                suggestion_example: finding.suggestion_example.clone(),
            })
            .collect();
        self.entries.insert(
            key,
            CachedFile {
                hash,
                findings: cached_findings,
            },
        );
        self.dirty = true;
    }

    fn save(&mut self) {
        if !self.dirty {
            return;
        }

        let mut out = String::new();
        out.push_str(&format!("v1|{}\n", self.fingerprint));

        let mut keys = self.entries.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        for key in keys {
            let Some(entry) = self.entries.get(&key) else {
                continue;
            };
            out.push_str(&format!("F|{}|{}\n", key, entry.hash));
            for finding in &entry.findings {
                out.push_str(&format!(
                    "R|{}|{}|{}|{}|{}|{}|{}|{}\n",
                    key,
                    finding.rule_id,
                    finding.line,
                    finding.column,
                    escape_field(&finding.message),
                    escape_field(&finding.snippet),
                    encode_optional(finding.suggestion.as_deref()),
                    encode_optional(finding.suggestion_example.as_deref()),
                ));
            }
        }

        if let Some(parent) = self.cache_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&self.cache_file, out);
        self.dirty = false;
    }
}

fn hash_content(content: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    content.hash(&mut hasher);
    hasher.finish()
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn split_fields(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (idx, ch) in line.char_indices() {
        if ch == '|' {
            out.push(&line[start..idx]);
            start = idx + 1;
        }
    }
    out.push(&line[start..]);
    out
}

fn encode_optional(value: Option<&str>) -> String {
    match value {
        Some(v) => escape_field(v),
        None => "~".to_string(),
    }
}

fn decode_optional(value: &str) -> Option<String> {
    if value == "~" {
        None
    } else {
        Some(unescape_field(value))
    }
}

fn escape_field(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '|' => out.push_str("\\p"),
            _ => out.push(ch),
        }
    }
    out
}

fn unescape_field(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('p') => out.push('|'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
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
        assert!(targets
            .iter()
            .any(|p| p.ends_with("crates/a") || p.ends_with("crates\\a")));
        assert!(targets
            .iter()
            .any(|p| p.ends_with("crates/b") || p.ends_with("crates\\b")));

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
        let findings = scan_files(&files, &rules, true);

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

fn matches_any_pattern(path: &Path, root: &Path, patterns: &[CompiledPattern]) -> bool {
    patterns.iter().any(|pattern| matches_pattern(path, root, pattern))
}

#[derive(Debug, Clone)]
struct CompiledPattern {
    cleaned: String,
    has_wildcards: bool,
    has_slash: bool,
}

fn compile_patterns(patterns: &[String]) -> Vec<CompiledPattern> {
    patterns
        .iter()
        .filter_map(|pattern| {
            let cleaned = pattern
                .trim()
                .trim_start_matches("./")
                .trim_end_matches('/')
                .to_string();
            if cleaned.is_empty() {
                return None;
            }
            Some(CompiledPattern {
                has_wildcards: cleaned.contains('*') || cleaned.contains('?'),
                has_slash: cleaned.contains('/'),
                cleaned,
            })
        })
        .collect()
}

fn matches_pattern(path: &Path, root: &Path, pattern: &CompiledPattern) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let basename = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    let cleaned = pattern.cleaned.as_str();

    if !pattern.has_wildcards && !pattern.has_slash {
        return normalized.split('/').any(|part| part == cleaned) || basename == cleaned;
    }
    if !pattern.has_slash {
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
