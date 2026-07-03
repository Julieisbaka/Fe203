use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::finding::Finding;

#[derive(Debug, Clone)]
pub(crate) struct CachedFinding {
    pub(crate) rule_id: String,
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) message: String,
    pub(crate) snippet: String,
    pub(crate) suggestion: Option<String>,
    pub(crate) suggestion_example: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedFile {
    hash: u64,
    findings: Vec<CachedFinding>,
}

pub(crate) struct ScanCache {
    cache_file: PathBuf,
    fingerprint: String,
    entries: HashMap<String, CachedFile>,
    dirty: bool,
}

impl ScanCache {
    pub(crate) fn load(cache_file: &Path, fingerprint: &str) -> Self {
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

    pub(crate) fn lookup<'a>(&'a self, file: &Path, hash: u64) -> Option<&'a [CachedFinding]> {
        let key = normalize_path(file);
        let cached = self.entries.get(&key)?;
        if cached.hash != hash {
            return None;
        }
        Some(&cached.findings)
    }

    pub(crate) fn store(&mut self, file: &Path, hash: u64, findings: &[Finding]) {
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

    pub(crate) fn save(&mut self) {
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

pub(crate) fn hash_content(content: &str) -> u64 {
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
