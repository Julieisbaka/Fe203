//! End-to-end test: fixture files on disk -> discovery -> rules -> findings.
// fe203-ignore-file all
// The nature of this file is that it violates many rules, so that we cant test the tool against it, as such we ignore all warnings.

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
    let api_key = "sk_live_123";
    let secret = "shhh";
    let _access_token = "ghp_1234567890abcdef";
    let _database_url = "postgres://user:pass@db.local/app";
    //
    let _ = regex::Regex::new(r"(a+)+$");
    let _ = regex::Regex::new(r".*token.*.*");
    let _ = regex::Regex::new(r"foo||bar");
    let _ = regex::RegexBuilder::new(format!("{}", pattern));
    let valid_name = regex::Regex::new("[a-z]+").is_match(input);
    let unused = 1;
    const MAX_RETRY: usize = 3;
    let (used_left, unused_right) = (1, 2);
    let _ = used_left;
}

fn shell_and_paths(user: &str) {
    std::process::Command::new("ls").arg("-la");
    std::process::Command::new("sh").arg("-c").arg(format!("echo {}", user));
    let shell_home = std::env::var("HOME").unwrap();
    std::process::Command::new("sh").arg("-c").arg(shell_home);
    let base = std::path::PathBuf::from("data");
    let _ = base.join("../secret");
    let _ = base.join(user_input);
}

#[test]
fn disconnected_test() {
    assert_eq!(2, 1 + 1);
}
"#;

#[test]
fn full_pipeline_finds_all_requested_patterns() {
    let dir = fixture_dir("pipeline");
    std::fs::write(dir.join("fixture.rs"), FIXTURE).unwrap();

    let registry = all_rules();
    let rules: Vec<&dyn Rule> = registry.iter().map(|r| r.as_ref()).collect();
    let mut files = Vec::new();
    discover_files(
        &dir,
        &Config::default().exclude,
        &Config::default().include,
        &mut files,
    );
    let findings = scan_files(&files, &rules, true);

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
            "FE043", // token
            "FE044", // credential URL
            "FE060", // clamp-like chain
            "FE061", // empty doc comment
            "FE062", // empty comment
            "FE063", // bounded
            "FE063", // valid_name
            "FE063", // password
            "FE063", // api_key
            "FE063", // secret
            "FE063", // unused
            "FE063", // unused_right
            "FE064", // unused constant
            "FE065", // test without product-code reference
            "FE075", // assert-only test without product calls
            "FE080", // nested regex quantifier
            "FE081", // suspicious regex
            "FE081", // suspicious regex
            "FE082", // dynamic regex construction
            "FE083", // unanchored validation regex
            "FE100", // command execution presence (ls)
            "FE100", // command execution presence (sh)
            "FE100", // command execution presence (sh env)
            "FE101", // shell string injection
            "FE101", // shell env var injection
            "FE120", // path traversal literal
            "FE121", // unsanitized path input
        ]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_disables_categories_and_rules() {
    let dir = fixture_dir("config");
    std::fs::write(dir.join("fixture.rs"), FIXTURE).unwrap();

    let config = Config::parse(
        "[rulesets]\ndebug = false\nsecrets = false\nlint = false\nregex = false\nshell = false\npath = false\n[rules]\nFE004 = true\n",
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
    let findings = scan_files(&files, &rules, true);

    let mut ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
    ids.sort();
    // Only unsafe rules plus the explicitly re-enabled panic! rule remain.
    assert_eq!(ids, ["FE004", "FE020", "FE021"]);

    let _ = std::fs::remove_dir_all(&dir);
}
