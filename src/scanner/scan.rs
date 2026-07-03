use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use crate::finding::Finding;
use crate::rules::lint::suppressions::dead_suppression_findings;
use crate::rules::{FileContext, Rule};

use super::cache::{hash_content, ScanCache};

/// Cache configuration used when creating a scan run.
pub struct ScanCacheOptions<'a> {
    /// Fingerprint string representing active rules/config for compatibility.
    pub fingerprint: &'a str,
    /// Cache file location.
    pub cache_file: &'a Path,
}

/// Stateful scanner session reused across chunk scans in one CLI run.
pub struct ScanRun<'a> {
    rules: &'a [&'a dyn Rule],
    rule_map: HashMap<&'static str, &'a dyn Rule>,
    cache_state: Option<ScanCache>,
}

impl<'a> ScanRun<'a> {
    /// Creates a new scan session and initializes optional cache state.
    pub fn new(rules: &'a [&'a dyn Rule], cache: Option<ScanCacheOptions<'_>>) -> Self {
        let rule_map = rules.iter().map(|rule| (rule.id(), *rule)).collect();
        let cache_state = cache.map(|opts| ScanCache::load(opts.cache_file, opts.fingerprint));
        ScanRun {
            rules,
            rule_map,
            cache_state,
        }
    }

    /// Scans one chunk of files and returns findings in deterministic order.
    pub fn scan_chunk(&mut self, files: &[PathBuf], use_prefilter: bool) -> Vec<Finding> {
        let mut findings = Vec::new();
        let scanned = scan_files_in_workers(
            files,
            self.rules,
            &self.rule_map,
            use_prefilter,
            self.cache_state.as_ref(),
        );

        for scanned_file in scanned {
            if scanned_file.cache_miss {
                if let Some(state) = &mut self.cache_state {
                    state.store(
                        &scanned_file.file,
                        scanned_file.hash,
                        &scanned_file.findings,
                    );
                }
            }
            findings.extend(scanned_file.findings);
        }

        findings.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.column.cmp(&b.column))
                .then(a.rule_id.cmp(b.rule_id))
                .then(a.message.cmp(&b.message))
        });
        findings
    }

    /// Flushes cache updates to disk.
    pub fn finish(&mut self) {
        if let Some(state) = &mut self.cache_state {
            state.save();
        }
    }
}

/// Convenience stateless wrapper for scanning without cache.
pub fn scan_files(files: &[PathBuf], rules: &[&dyn Rule], use_prefilter: bool) -> Vec<Finding> {
    let mut run = ScanRun::new(rules, None);
    let findings = run.scan_chunk(files, use_prefilter);
    run.finish();
    findings
}

/// Convenience wrapper for scanning with optional cache.
pub fn scan_files_with_cache(
    files: &[PathBuf],
    rules: &[&dyn Rule],
    use_prefilter: bool,
    cache: Option<ScanCacheOptions<'_>>,
) -> Vec<Finding> {
    let mut run = ScanRun::new(rules, cache);
    let findings = run.scan_chunk(files, use_prefilter);
    run.finish();
    findings
}

#[derive(Debug)]
struct ScannedFile {
    /// Source file path.
    file: PathBuf,
    /// Hash of file content used for cache keying.
    hash: u64,
    /// Findings produced for this file.
    findings: Vec<Finding>,
    /// True when file findings came from active scan and should be stored.
    cache_miss: bool,
}

/// Scans files in parallel using per-thread local result vectors.
fn scan_files_in_workers(
    files: &[PathBuf],
    rules: &[&dyn Rule],
    rule_map: &HashMap<&'static str, &dyn Rule>,
    use_prefilter: bool,
    cache: Option<&ScanCache>,
) -> Vec<ScannedFile> {
    if files.is_empty() {
        return Vec::new();
    }

    let worker_count = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(files.len())
        .max(1);

    if worker_count == 1 {
        let mut out = Vec::with_capacity(files.len());
        for file in files {
            if let Some(scanned) = scan_file_entry(file, rules, rule_map, use_prefilter, cache) {
                out.push(scanned);
            }
        }
        out.sort_by(|a, b| a.file.cmp(&b.file));
        return out;
    }

    let next = AtomicUsize::new(0);
    let mut out = Vec::with_capacity(files.len());
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            handles.push(scope.spawn(|| {
                let mut local = Vec::new();
                loop {
                    let idx = next.fetch_add(1, Ordering::Relaxed);
                    if idx >= files.len() {
                        break;
                    }
                    if let Some(scanned) =
                        scan_file_entry(&files[idx], rules, rule_map, use_prefilter, cache)
                    {
                        local.push(scanned);
                    }
                }
                local
            }));
        }
        for handle in handles {
            if let Ok(mut local) = handle.join() {
                out.append(&mut local);
            }
        }
    });

    out.sort_by(|a, b| a.file.cmp(&b.file));
    out
}

/// Scans one file entry and resolves cache hit/miss behavior.
fn scan_file_entry(
    file: &PathBuf,
    rules: &[&dyn Rule],
    rule_map: &HashMap<&'static str, &dyn Rule>,
    use_prefilter: bool,
    cache: Option<&ScanCache>,
) -> Option<ScannedFile> {
    let Ok(content) = std::fs::read_to_string(file) else {
        eprintln!("warning: skipping unreadable file {}", file.display());
        return None;
    };

    let file_hash = hash_content(&content);
    if let Some(cached) = cache.and_then(|state| state.lookup(file, file_hash)) {
        let findings = cached
            .iter()
            .filter_map(|entry| {
                let rule = rule_map.get(entry.rule_id.as_str())?;
                Some(Finding {
                    rule_id: rule.id(),
                    rule_name: rule.name(),
                    category: rule.category(),
                    severity: rule.severity(),
                    file: file.clone(),
                    line: entry.line,
                    column: entry.column,
                    message: entry.message.clone(),
                    snippet: entry.snippet.clone(),
                    suggestion: entry.suggestion.clone(),
                    suggestion_example: entry.suggestion_example.clone(),
                })
            })
            .collect();
        return Some(ScannedFile {
            file: file.clone(),
            hash: file_hash,
            findings,
            cache_miss: false,
        });
    }

    let findings = scan_single_file(file, &content, rules, use_prefilter);
    Some(ScannedFile {
        file: file.clone(),
        hash: file_hash,
        findings,
        cache_miss: true,
    })
}

/// Runs all enabled rules against one file's content.
fn scan_single_file(
    file: &Path,
    content: &str,
    rules: &[&dyn Rule],
    use_prefilter: bool,
) -> Vec<Finding> {
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
