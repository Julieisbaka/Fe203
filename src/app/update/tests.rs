use super::*;

#[cfg(unix)]
#[test]
fn replace_binary_in_place_unix_stages_with_unique_name() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!(
        "fe203-test-replace-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create test dir");

    let current_exe = dir.join("fe203");
    let replacement = dir.join("fe203-new");
    std::fs::write(&current_exe, b"old-binary").expect("write current_exe");
    std::fs::write(&replacement, b"new-binary").expect("write replacement");

    // Set the current binary executable.
    std::fs::set_permissions(&current_exe, std::fs::Permissions::from_mode(0o755))
        .expect("set permissions");

    super::platform::replace_binary_in_place_unix(&current_exe, &replacement)
        .expect("replace should succeed");

    // The current path should now contain the new content.
    let contents = std::fs::read(&current_exe).expect("read replaced binary");
    assert_eq!(contents, b"new-binary");

    // The replacement was staged with a unique name; no stale `.new` file should remain.
    let leftover: Vec<_> = std::fs::read_dir(&dir)
        .expect("read dir")
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".fe203-update-")
        })
        .collect();
    assert!(
        leftover.is_empty(),
        "stale staging files found: {:?}",
        leftover.iter().map(|e| e.path()).collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn replace_binary_in_place_unix_succeeds_when_stale_new_file_exists() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!(
        "fe203-test-stale-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create test dir");

    let current_exe = dir.join("fe203");
    let replacement = dir.join("fe203-replacement");
    // Simulate a stale `.new` file left from a previous failed update.
    let stale = dir.join("fe203.new");
    std::fs::write(&current_exe, b"old-binary").expect("write current_exe");
    std::fs::write(&replacement, b"new-binary").expect("write replacement");
    std::fs::write(&stale, b"stale-content").expect("write stale file");
    std::fs::set_permissions(&current_exe, std::fs::Permissions::from_mode(0o755))
        .expect("set permissions");

    // Should succeed even though `fe203.new` already exists, because unique staging is used.
    super::platform::replace_binary_in_place_unix(&current_exe, &replacement)
        .expect("replace should succeed");

    let contents = std::fs::read(&current_exe).expect("read replaced binary");
    assert_eq!(contents, b"new-binary");

    // The stale `.new` file should remain untouched (we didn't need to use it).
    assert!(stale.exists(), "stale file should not have been removed");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parses_semver_triplet_variants() {
    assert_eq!(
        parse_semver_triplet("0.2.1"),
        Some(SemverTriplet {
            major: 0,
            minor: 2,
            patch: 1,
            prerelease: None,
        })
    );
    assert_eq!(
        parse_semver_triplet("v1.4.3-beta.1+meta"),
        Some(SemverTriplet {
            major: 1,
            minor: 4,
            patch: 3,
            prerelease: Some("beta.1".to_string()),
        })
    );
    assert_eq!(parse_semver_triplet("1.2"), None);
    assert_eq!(parse_semver_triplet("vv1.2.3"), None);
    assert_eq!(parse_semver_triplet("01.2.3"), None);
    assert_eq!(parse_semver_triplet("1.2.3-01"), None);
    assert_eq!(parse_semver_triplet("1.2.3+"), None);
}

#[test]
fn compares_prereleases_before_stable_versions() {
    let alpha = parse_semver_triplet("1.2.3-alpha").unwrap();
    let beta_two = parse_semver_triplet("1.2.3-beta.2").unwrap();
    let beta_eleven = parse_semver_triplet("1.2.3-beta.11").unwrap();
    let stable = parse_semver_triplet("1.2.3").unwrap();

    assert!(alpha < beta_two);
    assert!(beta_two < beta_eleven);
    assert!(beta_eleven < stable);
    assert_eq!(
        parse_semver_triplet("1.2.3+build.1"),
        parse_semver_triplet("1.2.3+build.2")
    );
}

#[test]
fn verifies_downloaded_binary_version_output_exactly() {
    assert!(binary_version_matches("fe203 1.2.3\n", "1.2.3"));
    assert!(!binary_version_matches("fe203 1.2.4\n", "1.2.3"));
    assert!(!binary_version_matches("fe203 1.2.30\n", "1.2.3"));
}

#[test]
fn parses_github_repo_slug() {
    assert_eq!(
        parse_github_repo_slug("https://github.com/Julieisbaka/Fe203"),
        Some("Julieisbaka/Fe203".to_string())
    );
    assert_eq!(parse_github_repo_slug("https://example.com/a/b"), None);
}

#[test]
fn target_asset_spec_is_os_aware() {
    let windows = types::target_asset_spec("windows", "x86_64").unwrap();
    assert_eq!(windows.suffix, "x86_64-pc-windows-msvc.zip");
    let linux = types::target_asset_spec("linux", "x86_64").unwrap();
    assert_eq!(linux.suffix, "x86_64-unknown-linux-gnu.tar.gz");
    let mac = types::target_asset_spec("macos", "x86_64").unwrap();
    assert_eq!(mac.suffix, "x86_64-apple-darwin.tar.gz");
    assert!(types::target_asset_spec("linux", "aarch64").is_none());
}

#[test]
fn parses_latest_release_json_and_asset() {
    let json = r#"{
  "tag_name": "v0.2.1",
  "assets": [
    {
      "name": "fe203-v0.2.1-x86_64-pc-windows-msvc.zip",
      "browser_download_url": "https://example.invalid/fe203-win.zip"
    },
    {
      "name": "fe203-v0.2.1-x86_64-unknown-linux-gnu.tar.gz",
      "browser_download_url": "https://example.invalid/fe203-linux.tar.gz"
    }
  ]
}"#;

    let info = release::parse_latest_release_json(
        json,
        types::target_asset_spec("linux", "x86_64").expect("linux x86_64 spec"),
    )
    .unwrap();
    assert_eq!(info.version_text, "0.2.1");
    assert_eq!(
        info.asset_url,
        "https://example.invalid/fe203-linux.tar.gz".to_string()
    );
}

#[test]
fn release_asset_url_must_belong_to_the_matching_asset() {
    let json = r#"{
  "tag_name": "v0.2.1",
  "assets": [
    { "name": "fe203-v0.2.1-x86_64-unknown-linux-gnu.tar.gz" },
    {
      "name": "other-asset.zip",
      "browser_download_url": "https://example.invalid/other.zip"
    }
  ]
}"#;
    let spec = types::target_asset_spec("linux", "x86_64").unwrap();
    let parsed = release::parse_latest_release_json(json, spec).unwrap();
    assert!(parsed.asset_url.is_empty());
}
