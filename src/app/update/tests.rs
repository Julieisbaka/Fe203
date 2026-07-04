use super::*;

#[test]
fn parses_semver_triplet_variants() {
    assert_eq!(
        parse_semver_triplet("0.2.1"),
        Some(SemverTriplet {
            major: 0,
            minor: 2,
            patch: 1,
        })
    );
    assert_eq!(
        parse_semver_triplet("v1.4.3-beta.1+meta"),
        Some(SemverTriplet {
            major: 1,
            minor: 4,
            patch: 3,
        })
    );
    assert_eq!(parse_semver_triplet("1.2"), None);
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
