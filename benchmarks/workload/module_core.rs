#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};

pub struct EventRecord {
    pub id: u64,
    pub source: String,
    pub payload: String,
    pub severity: u8,
}

pub struct EventStore {
    records: Vec<EventRecord>,
    by_source: HashMap<String, Vec<u64>>,
    metrics: BTreeMap<String, usize>,
}

impl EventStore {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            by_source: HashMap::new(),
            metrics: BTreeMap::new(),
        }
    }

    pub fn push(&mut self, rec: EventRecord) {
        self.by_source
            .entry(rec.source.clone())
            .or_default()
            .push(rec.id);
        *self.metrics.entry("records_total".to_string()).or_insert(0) += 1;
        if rec.severity > 5 {
            *self.metrics.entry("high_severity".to_string()).or_insert(0) += 1;
        }
        self.records.push(rec);
    }

    pub fn find_by_source(&self, source: &str) -> Vec<&EventRecord> {
        self.records
            .iter()
            .filter(|rec| rec.source == source)
            .collect()
    }

    pub fn search_payload(&self, term: &str) -> Vec<&EventRecord> {
        self.records
            .iter()
            .filter(|rec| rec.payload.contains(term))
            .collect()
    }

    pub fn summarize(&self) -> String {
        let mut out = String::new();
        out.push_str("summary\n");
        out.push_str(&format!("records={}\n", self.records.len()));
        for (key, value) in &self.metrics {
            out.push_str(&format!("metric.{key}={value}\n"));
        }
        out
    }
}

pub fn normalize_lines(input: &str) -> Vec<String> {
    input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.to_ascii_lowercase())
        .collect()
}

pub fn fold_counts(lines: &[String]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for line in lines {
        for token in line.split_whitespace() {
            *counts.entry(token.to_string()).or_insert(0) += 1;
        }
    }
    counts
}

pub fn run_sample() -> String {
    let input = "alpha beta beta gamma alpha alpha";
    let lines = normalize_lines(input);
    let counts = fold_counts(&lines);
    let mut rendered = String::new();
    let mut keys: Vec<_> = counts.keys().cloned().collect();
    keys.sort();
    for key in keys {
        let value = counts.get(&key).copied().unwrap_or(0);
        rendered.push_str(&format!("{key}:{value}\n"));
    }
    rendered
}

pub fn lots_of_branching(value: i32) -> i32 {
    match value {
        0 => 0,
        1 => 1,
        2 => 1,
        3 => 2,
        4 => 3,
        5 => 5,
        6 => 8,
        7 => 13,
        8 => 21,
        9 => 34,
        10 => 55,
        11 => 89,
        12 => 144,
        13 => 233,
        14 => 377,
        _ => {
            let mut a = 0;
            let mut b = 1;
            for _ in 0..value.max(0) {
                let next = a + b;
                a = b;
                b = next;
            }
            a
        }
    }
}

pub fn matrix_mul(a: &[Vec<i64>], b: &[Vec<i64>]) -> Vec<Vec<i64>> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let rows = a.len();
    let cols = b[0].len();
    let mut out = vec![vec![0; cols]; rows];
    for row in 0..rows {
        for col in 0..cols {
            let mut acc = 0;
            for k in 0..b.len() {
                let left = a[row].get(k).copied().unwrap_or(0);
                let right = b.get(k).and_then(|r| r.get(col)).copied().unwrap_or(0);
                acc += left * right;
            }
            out[row][col] = acc;
        }
    }
    out
}

pub fn string_heavy_render(input: &[&str]) -> String {
    let mut out = String::new();
    for item in input {
        out.push('[');
        out.push_str(&item.replace('"', "\\\""));
        out.push(']');
        out.push('\n');
    }
    out
}
