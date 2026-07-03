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
    let mut out = String::with_capacity(512);
    let mut first = true;

    let mut rule_parts: Vec<(&str, &str, &str, &str)> = enabled
        .iter()
        .map(|rule| {
            (
                rule.id(),
                rule.name(),
                rule.category().name(),
                rule.severity().name(),
            )
        })
        .collect();
    rule_parts.sort_unstable();
    for (id, name, category, severity) in rule_parts {
        append_part(&mut out, &mut first);
        out.push_str(id);
        out.push(':');
        out.push_str(name);
        out.push(':');
        out.push_str(category);
        out.push(':');
        out.push_str(severity);
    }

    let mut rulesets: Vec<(&str, bool)> = config
        .rulesets
        .iter()
        .map(|(key, value)| (key.as_str(), *value))
        .collect();
    rulesets.sort_unstable_by(|a, b| a.0.cmp(b.0));
    for (key, value) in rulesets {
        append_part(&mut out, &mut first);
        out.push_str("rs:");
        out.push_str(key);
        out.push('=');
        out.push_str(if value { "true" } else { "false" });
    }

    let mut rules: Vec<(&str, bool)> = config
        .rules
        .iter()
        .map(|(key, value)| (key.as_str(), *value))
        .collect();
    rules.sort_unstable_by(|a, b| a.0.cmp(b.0));
    for (key, value) in rules {
        append_part(&mut out, &mut first);
        out.push_str("r:");
        out.push_str(key);
        out.push('=');
        out.push_str(if value { "true" } else { "false" });
    }

    let mut severity: Vec<(&str, &str)> = config
        .severity
        .iter()
        .map(|(key, value)| (key.as_str(), value.name()))
        .collect();
    severity.sort_unstable_by(|a, b| a.0.cmp(b.0));
    for (key, value) in severity {
        append_part(&mut out, &mut first);
        out.push_str("s:");
        out.push_str(key);
        out.push('=');
        out.push_str(value);
    }

    append_part(&mut out, &mut first);
    out.push_str("exclude:");
    append_csv_sorted(&mut out, &config.exclude);

    append_part(&mut out, &mut first);
    out.push_str("include:");
    append_csv_sorted(&mut out, &config.include);

    append_part(&mut out, &mut first);
    out.push_str("prefilter:");
    out.push_str(if use_prefilter { "true" } else { "false" });

    out
}

fn append_part(out: &mut String, first: &mut bool) {
    if *first {
        *first = false;
    } else {
        out.push('|');
    }
}

fn append_csv_sorted(out: &mut String, values: &[String]) {
    let mut sorted: Vec<&str> = values.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    for (idx, value) in sorted.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(value);
    }
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
