use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::finding::Finding;
use crate::rules::Rule;
use crate::scanner;

/// Aggregated scan output for the CLI reporting layer.
pub(super) struct ScanOutcome {
    /// Number of files actually scanned in this invocation.
    pub files_scanned: usize,
    /// Collected findings after all targets and chunks are processed.
    pub findings: Vec<Finding>,
}

/// Executes discovery and scanning across all requested targets.
///
/// This function streams files in chunks to keep memory bounded while still
/// preserving deterministic output ordering from scanner internals.
pub(super) fn execute_scan(
    targets: &[PathBuf],
    config: &Config,
    enabled: &[&dyn Rule],
    show_progress: bool,
    use_prefilter: bool,
) -> Result<ScanOutcome, String> {
    let mut files_scanned = 0usize;
    let mut files_discovered = 0usize;
    let mut findings = Vec::new();
    // Chunked scanning balances throughput and memory usage on large trees.
    let chunk_size = 256usize;
    let mut chunk = Vec::with_capacity(chunk_size);
    let discover_start = Instant::now();
    if show_progress {
        eprintln!("info: discovering files...");
    }

    let scan_fingerprint = scan_fingerprint(enabled, config, use_prefilter);
    let cache_file = default_scan_cache_file();
    // Environment options are evaluated once per run.
    let cache_disabled = std::env::var("FE203_NO_CACHE").is_ok();
    let mut scan_run = scanner::ScanRun::new(
        enabled,
        if cache_disabled {
            None
        } else {
            Some(scanner::ScanCacheOptions {
                fingerprint: &scan_fingerprint,
                cache_file: &cache_file,
            })
        },
    );
    let scan_start = Instant::now();

    for target in targets {
        if !target.exists() {
            return Err(format!("path does not exist: {}", target.display()));
        }

        let mut on_file = |path: PathBuf| {
            files_discovered += 1;
            chunk.push(path);
            if chunk.len() >= chunk_size {
                let current = std::mem::take(&mut chunk);
                files_scanned += current.len();
                let mut scanned = scan_run.scan_chunk(&current, use_prefilter);
                findings.append(&mut scanned);
                if show_progress {
                    let elapsed = scan_start.elapsed().as_secs_f64().max(0.001);
                    let rate = files_scanned as f64 / elapsed;
                    eprintln!(
                        "info: scanned {}/{} files ({:.1} files/s)",
                        files_scanned, files_discovered, rate
                    );
                }
            }
        };
        scanner::discover_files_stream(target, &config.exclude, &config.include, &mut on_file);
    }

    if !chunk.is_empty() {
        files_scanned += chunk.len();
        let mut scanned = scan_run.scan_chunk(&chunk, use_prefilter);
        findings.append(&mut scanned);
    }

    scan_run.finish();

    if show_progress {
        eprintln!(
            "info: discovered {} files in {}",
            files_discovered,
            format_duration(discover_start.elapsed())
        );
        eprintln!(
            "info: scanned {} files with {} rules...",
            files_scanned,
            enabled.len()
        );
        eprintln!(
            "info: scan complete in {} ({} findings)",
            format_duration(scan_start.elapsed()),
            findings.len()
        );
    }

    Ok(ScanOutcome {
        files_scanned,
        findings,
    })
}

/// Returns the default on-disk scan cache path for the current workspace.
fn default_scan_cache_file() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".fe203")
        .join("scan-cache.v1")
}

/// Builds a deterministic fingerprint string for cache keying.
fn scan_fingerprint(enabled: &[&dyn Rule], config: &Config, use_prefilter: bool) -> String {
    let mut parts = Vec::new();
    let mut rule_ids = enabled
        .iter()
        .map(|rule| {
            format!(
                "{}:{}:{}:{}",
                rule.id(),
                rule.name(),
                rule.category().name(),
                rule.severity().name()
            )
        })
        .collect::<Vec<_>>();
    rule_ids.sort();
    parts.extend(rule_ids);

    let mut rulesets = config
        .rulesets
        .iter()
        .map(|(k, v)| format!("rs:{k}={v}"))
        .collect::<Vec<_>>();
    rulesets.sort();
    parts.extend(rulesets);

    let mut rules = config
        .rules
        .iter()
        .map(|(k, v)| format!("r:{k}={v}"))
        .collect::<Vec<_>>();
    rules.sort();
    parts.extend(rules);

    let mut severity = config
        .severity
        .iter()
        .map(|(k, v)| format!("s:{k}={}", v.name()))
        .collect::<Vec<_>>();
    severity.sort();
    parts.extend(severity);

    let mut exclude = config.exclude.clone();
    exclude.sort();
    parts.push(format!("exclude:{}", exclude.join(",")));

    let mut include = config.include.clone();
    include.sort();
    parts.push(format!("include:{}", include.join(",")));

    parts.push(format!("prefilter:{use_prefilter}"));
    parts.join("|")
}

/// Renders a compact human-readable duration.
fn format_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis < 1_000 {
        format!("{millis}ms")
    } else {
        let seconds = duration.as_secs_f64();
        format!("{seconds:.2}s")
    }
}
