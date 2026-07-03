mod cache;
mod discovery;
mod patterns;
mod scan;

pub use discovery::{discover_files, discover_files_stream, expand_manifest_targets};
pub use scan::{scan_files, scan_files_with_cache, ScanCacheOptions};

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::rules::{all_rules, Rule};

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fe203-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn discovers_rust_files_and_excludes() {
        let dir = temp_dir("discover");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::create_dir_all(dir.join("target")).unwrap();
        std::fs::write(dir.join("src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(dir.join("src/notes.txt"), "not rust\n").unwrap();
        std::fs::write(dir.join("target/gen.rs"), "fn skipped() {}\n").unwrap();

        let mut files = Vec::new();
        discover_files(&dir, &["target".to_string()], &[], &mut files);

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("src/main.rs") || files[0].ends_with("src\\main.rs"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expands_workspace_members() {
        let dir = temp_dir("workspace-members");
        std::fs::create_dir_all(dir.join("crates/a/src")).unwrap();
        std::fs::create_dir_all(dir.join("crates/b/src")).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/a\", \"crates/b\"]\n",
        )
        .unwrap();

        let targets = expand_manifest_targets(&[dir.clone()]);
        assert!(targets
            .iter()
            .any(|p| p.ends_with("crates/a") || p.ends_with("crates\\a")));
        assert!(targets
            .iter()
            .any(|p| p.ends_with("crates/b") || p.ends_with("crates\\b")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_reports_expected_rules() {
        let dir = temp_dir("scan");
        std::fs::write(
            dir.join("bad.rs"),
            "fn f() {\n    todo!();\n    unsafe { x() }\n}\nlet password = \"hunter2\";\n",
        )
        .unwrap();

        let registry = all_rules();
        let rules: Vec<&dyn Rule> = registry.iter().map(|r| r.as_ref()).collect();
        let mut files = Vec::new();
        discover_files(&dir, &[], &[], &mut files);
        let findings = scan_files(&files, &rules, true);

        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        let mut ids = ids;
        ids.sort();
        assert_eq!(ids, ["FE001", "FE020", "FE040", "FE063"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discovers_included_files() {
        let dir = temp_dir("include");
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        std::fs::write(dir.join("build.rs"), "fn main() {}\n").unwrap();

        let mut files = Vec::new();
        discover_files(&dir, &[], &["Cargo.toml".to_string()], &mut files);

        assert!(files
            .iter()
            .any(|path| path.ends_with("Cargo.toml") || path.ends_with("Cargo.toml")));
        assert!(files
            .iter()
            .any(|path| path.ends_with("build.rs") || path.ends_with("build.rs")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn glob_matches_gitignore_entries() {
        let dir = temp_dir("glob");
        std::fs::create_dir_all(dir.join("nested/debug")).unwrap();
        std::fs::write(dir.join("nested/debug/file.pdb"), "x").unwrap();
        std::fs::write(dir.join("nested/debug/cache.rs.bk"), "x").unwrap();

        let mut files = Vec::new();
        discover_files(
            &dir,
            &[
                "debug".to_string(),
                "*.pdb".to_string(),
                "**/*.rs.bk".to_string(),
            ],
            &[],
            &mut files,
        );
        assert!(files.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ignores_partial_directory_names() {
        let dir = temp_dir("partial");
        std::fs::create_dir_all(dir.join("mytarget")).unwrap();
        std::fs::write(dir.join("mytarget/keep.rs"), "fn keep() {}\n").unwrap();

        let mut files = Vec::new();
        discover_files(&dir, &["target".to_string()], &[], &mut files);

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("mytarget/keep.rs") || files[0].ends_with("mytarget\\keep.rs"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
