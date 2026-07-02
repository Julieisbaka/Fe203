//! `fe203.toml` configuration.
//!
//! Zero-dependency parser for the small TOML subset Fe203 needs:
//! `[section]` headers, `key = true/false`, `key = "string"`, and
//! `key = ["a", "b"]` arrays of strings.
//!
//! ```toml
//! [rulesets]
//! debug = true
//! unsafe = true
//! secrets = true
//! lint = true
//! regex = true
//!
//! [rules]
//! FE003 = false
//!
//! [paths]
//! exclude = ["target", ".git"]
//! include = ["Cargo.toml"]
//! ```

use std::collections::HashMap;
use std::path::Path;

use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct Config {
    /// Category name -> enabled. Categories absent from the map default to enabled.
    pub rulesets: HashMap<String, bool>,
    /// Rule ID -> enabled. Overrides the category toggle.
    pub rules: HashMap<String, bool>,
    /// Directory/file names to skip during discovery.
    pub exclude: Vec<String>,
    /// Extra file names to include during discovery, even if they are not `.rs` files.
    pub include: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            rulesets: HashMap::new(),
            rules: HashMap::new(),
            exclude: vec!["target".to_string(), ".git".to_string()],
            include: Vec::new(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
        Config::parse(&text)
            .map_err(|e| format!("invalid config {}: {e}", path.display()))
    }

    /// Whether a rule should run: an explicit rule toggle wins, then the
    /// category toggle, then the default (enabled).
    pub fn rule_enabled(&self, rule: &dyn Rule) -> bool {
        if let Some(&enabled) = self.rules.get(rule.id()) {
            return enabled;
        }
        if let Some(&enabled) = self.rulesets.get(rule.category().name()) {
            return enabled;
        }
        true
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let mut config = Config::default();
        let mut section = String::new();

        for (line_no, raw) in text.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }

            if let Some(header) = line.strip_prefix('[') {
                let name = header
                    .strip_suffix(']')
                    .ok_or_else(|| format!("line {}: unterminated section header", line_no + 1))?;
                section = name.trim().to_lowercase();
                continue;
            }

            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: expected `key = value`", line_no + 1))?;
            let key = key.trim();
            let value = value.trim();

            match section.as_str() {
                "rulesets" => {
                    let enabled = parse_bool(value)
                        .ok_or_else(|| format!("line {}: expected true/false", line_no + 1))?;
                    config.rulesets.insert(key.to_lowercase(), enabled);
                }
                "rules" => {
                    let enabled = parse_bool(value)
                        .ok_or_else(|| format!("line {}: expected true/false", line_no + 1))?;
                    config.rules.insert(key.to_uppercase(), enabled);
                }
                "paths" => {
                    if key == "exclude" {
                        config.exclude = parse_string_array(value)
                            .ok_or_else(|| format!("line {}: expected array of strings", line_no + 1))?;
                    } else if key == "include" {
                        config.include = parse_string_array(value)
                            .ok_or_else(|| format!("line {}: expected array of strings", line_no + 1))?;
                    } else {
                        return Err(format!("line {}: unknown key `{key}` in [paths]", line_no + 1));
                    }
                }
                "" => return Err(format!("line {}: key outside of a section", line_no + 1)),
                other => return Err(format!("line {}: unknown section `[{other}]`", line_no + 1)),
            }
        }

        Ok(config)
    }

    /// Generates a fe203.toml template by copying safe exclusions from a
    /// workspace `.gitignore` if present.
    pub fn template_from_workspace(root: &Path) -> String {
        let mut exclude = default_excludes();
        if let Ok(text) = std::fs::read_to_string(root.join(".gitignore")) {
            exclude.extend(parse_gitignore_entries(&text));
        }
        dedup_strings(&mut exclude);

        let mut out = String::new();
        out.push_str("# Generated Fe203 configuration template\n");
        out.push_str("# Generated from your workspace .gitignore when available.\n\n");
        out.push_str("[rulesets]\n");
        out.push_str("debug = true\nunsafe = true\nsecrets = true\nlint = true\nregex = true\nshell = true\npath = true\n\n");
        out.push_str("[rules]\n");
        out.push_str("# FE003 = false   # allow ");
        // fe203-ignore FE003
        out.push_str("dbg!");
        out.push_str("()\n\n");
        out.push_str("[paths]\n");
        out.push_str(&format!("exclude = [{}]\n", join_string_list(&exclude)));
        out.push_str("include = [\"Cargo.toml\"]\n");
        out
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_string_array(value: &str) -> Option<Vec<String>> {
    let inner = value.strip_prefix('[')?.strip_suffix(']')?;
    let mut out = Vec::new();
    for item in inner.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let s = item.strip_prefix('"')?.strip_suffix('"')?;
        out.push(s.to_string());
    }
    Some(out)
}

fn default_excludes() -> Vec<String> {
    vec![
        "target".to_string(),
        "debug".to_string(),
        "*.pdb".to_string(),
        "**/*.rs.bk".to_string(),
        "**/mutants.out*/".to_string(),
        ".idea/".to_string(),
    ]
}

fn parse_gitignore_entries(text: &str) -> Vec<String> {
    let mut entries = Vec::new();
    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() || line.starts_with('!') {
            continue;
        }
        let trimmed = line.trim_start_matches("./").trim_start_matches('/').trim_end_matches('/');
        if !trimmed.is_empty() {
            entries.push(trimmed.to_string());
        }
    }
    entries
}

fn join_string_list(items: &[String]) -> String {
    items
        .iter()
        .map(|item| format!("\"{}\"", item))
        .collect::<Vec<_>>()
        .join(", ")
}

fn dedup_strings(items: &mut Vec<String>) {
    items.sort();
    items.dedup();
}

/// Removes a trailing `# comment`, respecting quoted strings.
fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_string = !in_string,
            '#' if !in_string => return &line[..i],
            _ => {}
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::all_rules;

    #[test]
    fn defaults_enable_everything() {
        let config = Config::default();
        for rule in all_rules() {
            assert!(config.rule_enabled(rule.as_ref()), "{} disabled", rule.id());
        }
        assert_eq!(config.exclude, ["target", ".git"]);
        assert!(config.include.is_empty());
    }

    #[test]
    fn ruleset_toggle_disables_category() {
        let config = Config::parse("[rulesets]\ndebug = false\n").unwrap();
        for rule in all_rules() {
            let expected = rule.category().name() != "debug";
            assert_eq!(config.rule_enabled(rule.as_ref()), expected, "{}", rule.id());
        }
    }

    #[test]
    fn rule_toggle_overrides_ruleset() {
        let config =
            Config::parse("[rulesets]\ndebug = false\n[rules]\nfe001 = true\n").unwrap();
        let rules = all_rules();
        let todo = rules.iter().find(|r| r.id() == "FE001").unwrap();
        let dbg = rules.iter().find(|r| r.id() == "FE003").unwrap();
        assert!(config.rule_enabled(todo.as_ref()));
        assert!(!config.rule_enabled(dbg.as_ref()));
    }

    #[test]
    fn parses_excludes_and_comments() {
        let config = Config::parse(
            "# top comment\n[paths]\nexclude = [\"target\", \"vendor\"] # trailing\ninclude = [\"Cargo.toml\", \"build.rs\"]\n",
        )
        .unwrap();
        assert_eq!(config.exclude, ["target", "vendor"]);
        assert_eq!(config.include, ["Cargo.toml", "build.rs"]);
    }

    #[test]
    fn rejects_unknown_section() {
        assert!(Config::parse("[nope]\nx = true\n").is_err());
    }

    #[test]
    fn generates_template_from_gitignore() {
        let dir = std::env::temp_dir().join(format!("fe203-template-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".gitignore"), "target\n*.cache\n# comment\n!keep\n").unwrap();

        let template = Config::template_from_workspace(&dir);
        assert!(template.contains("include = [\"Cargo.toml\"]"));
        assert!(template.contains("target"));
        assert!(template.contains("*.cache"));
        assert!(!template.contains("keep"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
