//! End-to-end test: fixture files on disk -> discovery -> rules -> findings.

use std::path::PathBuf;

use fe203::config::Config;
use fe203::rules::{all_rules, Rule};
use fe203::scanner::{discover_files, scan_files};

fn fixture_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fe203-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const FIXTURE: &str = r#"
///
pub unsafe fn raw_read() {}

fn work() {
    unsafe { raw_read() }
    todo!();
    unimplemented!();
    dbg!(42);
    panic!("nope");
    let bounded = value.max(min).min(max);
}

fn config() {
    let password = "hunter2";
    let api_key = "sk-123";
    let secret = "shhh";
    //
    let _ = regex::Regex::new(r"(a+)+$");
    let _ = regex::Regex::new(r".*token.*.*");
    let unused = 1;
    const MAX_RETRY: usize = 3;
}
"#;

#[test]
fn full_pipeline_finds_all_requested_patterns() {
    let dir = fixture_dir("pipeline");
    std::fs::write(dir.join("fixture.rs"), FIXTURE).unwrap();

    let registry = all_rules();
    let rules: Vec<&dyn Rule> = registry.iter().map(|r| r.as_ref()).collect();
    let mut files = Vec::new();
    discover_files(&dir, &Config::default().exclude, &Config::default().include, &mut files);
    let findings = scan_files(&files, &rules);

    let mut ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
    ids.sort();
    assert_eq!(
        ids,
        [
            "FE001", // todo!
            "FE002", // unimplemented!
            "FE003", // dbg!
            "FE004", // panic!
            "FE020", // unsafe block
            "FE021", // unsafe fn
            "FE040", // password
            "FE041", // api_key
            "FE042", // secret
            "FE060", // clamp-like chain
            "FE061", // empty doc comment
            "FE062", // empty comment
            "FE063", // bounded
            "FE063", // password
            "FE063", // api_key
            "FE063", // secret
            "FE063", // unused
            "FE064", // unused constant
            "FE080", // nested regex quantifier
            "FE081", // suspicious regex
        ]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_disables_categories_and_rules() {
    let dir = fixture_dir("config");
    std::fs::write(dir.join("fixture.rs"), FIXTURE).unwrap();

    let config = Config::parse(
        "[rulesets]\ndebug = false\nsecrets = false\nlint = false\nregex = false\n[rules]\nFE004 = true\n",
    )
    .unwrap();

    let registry = all_rules();
    let rules: Vec<&dyn Rule> = registry
        .iter()
        .map(|r| r.as_ref())
        .filter(|r| config.rule_enabled(*r))
        .collect();
    let mut files = Vec::new();
    discover_files(&dir, &config.exclude, &config.include, &mut files);
    let findings = scan_files(&files, &rules);

    let mut ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
    ids.sort();
    // Only unsafe rules plus the explicitly re-enabled panic! rule remain.
    assert_eq!(ids, ["FE004", "FE020", "FE021"]);

    let _ = std::fs::remove_dir_all(&dir);
}
