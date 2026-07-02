//! File discovery and scan orchestration.

use std::path::{Path, PathBuf};

use crate::finding::Finding;
use crate::rules::{FileContext, Rule};

/// Recursively collects `.rs` files under `root` into `out`, skipping any
/// directory or file whose name matches an `exclude` entry. If `root` is a
/// file it is added directly (regardless of extension) so users can scan
/// arbitrary files explicitly.
pub fn discover_files(root: &Path, exclude: &[String], include: &[String], out: &mut Vec<PathBuf>) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    walk(root, exclude, include, out);
}

fn walk(dir: &Path, exclude: &[String], include: &[String], out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();

    for path in paths {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if exclude.iter().any(|e| e == &name) {
            continue;
        }
        if path.is_dir() {
            walk(&path, exclude, include, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") || include.iter().any(|e| e == &name) {
            out.push(path);
        }
    }
}

/// Runs every enabled rule over every file and collects the findings,
/// ordered by file, then line, then rule ID.
pub fn scan_files(files: &[PathBuf], rules: &[&dyn Rule]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in files {
        let Ok(content) = std::fs::read_to_string(file) else {
            eprintln!("warning: skipping unreadable file {}", file.display());
            continue;
        };
        let ctx = FileContext::new(file, &content);
        for rule in rules {
            findings.extend(rule.scan(&ctx));
        }
    }
    findings.sort_by(|a, b| {
        (&a.file, a.line, a.column, a.rule_id).cmp(&(&b.file, b.line, b.column, b.rule_id))
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::all_rules;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fe203-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn discovers_only_rust_files_and_honors_excludes() {
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
        let findings = scan_files(&files, &rules);

        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        let mut ids = ids;
        ids.sort();
        assert_eq!(ids, ["FE001", "FE020", "FE040", "FE063"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discovers_included_project_files() {
        let dir = temp_dir("include");
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        std::fs::write(dir.join("build.rs"), "fn main() {}\n").unwrap();

        let mut files = Vec::new();
        discover_files(&dir, &[], &["Cargo.toml".to_string()], &mut files);

        assert!(files.iter().any(|path| path.ends_with("Cargo.toml") || path.ends_with("Cargo.toml")));
        assert!(files.iter().any(|path| path.ends_with("build.rs") || path.ends_with("build.rs")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
