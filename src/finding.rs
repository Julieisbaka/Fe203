//! Shared finding model: what a rule reports when it matches.
// fe203-ignore-file FE020

use std::fmt;
use std::path::PathBuf;

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    High,
    Critical,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Ruleset category a rule belongs to. Used for config toggles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Debug,
    Unsafe,
    Secrets,
    Lint,
    Regex,
    Shell,
    Path,
}

impl Category {
    pub fn name(self) -> &'static str {
        match self {
            Category::Debug => "debug",
            Category::Unsafe => "unsafe",
            Category::Secrets => "secrets",
            Category::Lint => "lint",
            Category::Regex => "regex",
            Category::Shell => "shell",
            Category::Path => "path",
        }
    }

    pub fn from_name(name: &str) -> Option<Category> {
        match name {
            "debug" => Some(Category::Debug),
            "unsafe" => Some(Category::Unsafe),
            "secrets" => Some(Category::Secrets),
            "lint" => Some(Category::Lint),
            "regex" => Some(Category::Regex),
            "shell" => Some(Category::Shell),
            "path" => Some(Category::Path),
            _ => None,
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A single issue found by a rule.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub file: PathBuf,
    /// 1-based line number.
    pub line: usize,
    /// 1-based column number.
    pub column: usize,
    pub message: String,
    pub snippet: String,
    pub suggestion: Option<String>,
}
