use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;

use crate::finding::Finding;
use crate::rules::lint::suppressions::dead_suppression_findings;
use crate::rules::{FileContext, Rule};

use super::cache::{hash_content, ScanCache};

pub struct ScanCacheOptions<'a> {
    pub fingerprint: &'a str,
    pub cache_file: &'a Path,
}

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
        if let Some(state) = &mut cache_state {
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
            state.store(
                &scanned_file.file,
                scanned_file.hash,
                &scanned_file.findings,
            );
        }
        findings.extend(scanned_file.findings);
    }

    if let Some(state) = &mut cache_state {
        state.save();
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
