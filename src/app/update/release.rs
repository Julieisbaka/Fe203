use std::process::Command;

use super::json_scan::{extract_json_string_field, find_asset_download_url};
use super::types::{current_target_asset_spec, ReleaseInfo, TargetAssetSpec};

#[cfg(windows)]
use super::platform::ps_single_quote_escape;

pub(super) fn latest_release_info() -> Result<ReleaseInfo, String> {
    let spec = current_target_asset_spec().ok_or_else(|| {
        format!(
            "self-update is unsupported on target {}-{}",
            std::env::consts::ARCH,
            std::env::consts::OS
        )
    })?;

    let json = fetch_latest_release_json()?;
    parse_latest_release_json(&json, spec)
        .ok_or_else(|| "failed to parse latest release metadata from GitHub".to_string())
}

fn fetch_latest_release_json() -> Result<String, String> {
    #[cfg(windows)]
    {
        let repo = super::parse_github_repo_slug(env!("CARGO_PKG_REPOSITORY")).ok_or_else(|| {
            format!(
                "cannot derive GitHub owner/repo from CARGO_PKG_REPOSITORY: {}",
                env!("CARGO_PKG_REPOSITORY")
            )
        })?;

        let script = format!(
            "$ErrorActionPreference='Stop';$repo='{repo}';Invoke-RestMethod -Headers @{{'User-Agent'='fe203'}} -Uri (\"https://api.github.com/repos/$repo/releases/latest\") | ConvertTo-Json -Depth 100;",
            repo = ps_single_quote_escape(&repo)
        );

        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &script,
            ])
            .output()
            .map_err(|err| format!("failed to query latest release from GitHub: {err}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "failed to query latest release from GitHub (exit {:?}): {}",
                output.status.code(),
                stderr.trim()
            ));
        }

        return String::from_utf8(output.stdout)
            .map_err(|_| "latest release response was not valid UTF-8".to_string());
    }

    #[cfg(unix)]
    {
        let repo = super::parse_github_repo_slug(env!("CARGO_PKG_REPOSITORY")).ok_or_else(|| {
            format!(
                "cannot derive GitHub owner/repo from CARGO_PKG_REPOSITORY: {}",
                env!("CARGO_PKG_REPOSITORY")
            )
        })?;
        let url = format!("https://api.github.com/repos/{repo}/releases/latest");

        let output = Command::new("curl")
            .args(["-fsSL", "-H", "User-Agent: fe203", &url])
            .output()
            .map_err(|err| format!("failed to query latest release from GitHub: {err}"))?;

        if output.status.success() {
            return String::from_utf8(output.stdout)
                .map_err(|_| "latest release response was not valid UTF-8".to_string());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "failed to query latest release from GitHub (exit {:?}): {}",
            output.status.code(),
            stderr.trim()
        ))
    }
}

pub(super) fn parse_latest_release_json(json: &str, spec: TargetAssetSpec) -> Option<ReleaseInfo> {
    let tag = extract_json_string_field(json, "tag_name")?;
    let tag_no_v = tag.trim().trim_start_matches('v').to_string();
    let version = super::parse_semver_triplet(&tag_no_v)?;

    let expected_a = format!("fe203-v{}-{}", tag_no_v, spec.suffix);
    let expected_b = format!("fe203-{}-{}", tag_no_v, spec.suffix);
    let asset_url = find_asset_download_url(json, &[&expected_a, &expected_b]).unwrap_or_default();

    Some(ReleaseInfo {
        version_text: tag_no_v,
        version,
        asset_url,
        archive_kind: spec.archive_kind,
        binary_name: spec.binary_name,
    })
}
