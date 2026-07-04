use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub(super) fn run_check_update(current_version: &str) -> i32 {
    match latest_release_info() {
        Ok(release) => {
            let Some(current) = parse_semver_triplet(current_version) else {
                eprintln!("error: invalid current version: {current_version}");
                return 2;
            };

            if release.version > current {
                println!(
                    "update available: {} -> {}",
                    current_version, release.version_text
                );
                if release.asset_url.is_empty() {
                    println!(
                        "note: no compatible release asset found for this OS/architecture; install manually from GitHub Releases"
                    );
                } else {
                    println!("run `fe203 --self-update` to install the latest release binary");
                }
            } else {
                println!("fe203 is up to date ({current_version})");
            }
            0
        }
        Err(err) => {
            eprintln!("error: {err}");
            2
        }
    }
}

pub(super) fn run_self_update(current_version: &str) -> i32 {
    match perform_self_update(current_version) {
        Ok(exit_code) => exit_code,
        Err(err) => {
            eprintln!("error: {err}");
            2
        }
    }
}

fn perform_self_update(current_version: &str) -> Result<i32, String> {
    let release = latest_release_info()?;
    let current = parse_semver_triplet(current_version)
        .ok_or_else(|| format!("invalid current version: {current_version}"))?;

    if release.version <= current {
        println!("fe203 is already up to date ({current_version})");
        return Ok(0);
    }
    if release.asset_url.is_empty() {
        return Err(
            "latest release does not provide a compatible asset for this OS/architecture"
                .to_string(),
        );
    }

    let exe = std::env::current_exe().map_err(|err| format!("cannot locate current executable: {err}"))?;
    if is_development_executable_path(&exe) {
        return Err(
            "refusing to self-update a development target binary (target/debug or target/release)"
                .to_string(),
        );
    }

    let tmp = make_temp_update_dir()?;
    let archive_path = tmp.join(release.archive_file_name());
    download_release_asset(&release.asset_url, &archive_path)?;
    extract_archive(&archive_path, &tmp, release.archive_kind)?;

    let extracted_binary = find_file_recursively(&tmp, release.binary_name)
        .ok_or_else(|| format!("downloaded archive did not contain {}", release.binary_name))?;

    #[cfg(windows)]
    {
        schedule_windows_replace_and_launch(&exe, &extracted_binary, &tmp, &release.version_text)?;
        println!(
            "updating to {}. The new version will launch automatically when this command exits.",
            release.version_text
        );
        Ok(0)
    }

    #[cfg(unix)]
    {
        replace_binary_in_place_unix(&exe, &extracted_binary)?;
        let _ = std::fs::remove_dir_all(&tmp);
        println!("updated to {}", release.version_text);
        launch_updated_binary(&exe)
    }
}

#[cfg(windows)]
fn schedule_windows_replace_and_launch(
    current_exe: &Path,
    replacement_binary: &Path,
    temp_dir: &Path,
    version_text: &str,
) -> Result<(), String> {
    let pid = std::process::id();
    let script = format!(
        "$ErrorActionPreference='Stop';\
$pidToWait={pid};\
while(Get-Process -Id $pidToWait -ErrorAction SilentlyContinue){{Start-Sleep -Milliseconds 200}};\
Copy-Item -Path '{replacement}' -Destination '{current}' -Force;\
& '{current}' --version;\
Remove-Item -Path '{temp_dir}' -Recurse -Force -ErrorAction SilentlyContinue;",
        pid = pid,
        replacement = ps_single_quote_escape(&replacement_binary.to_string_lossy()),
        current = ps_single_quote_escape(&current_exe.to_string_lossy()),
        temp_dir = ps_single_quote_escape(&temp_dir.to_string_lossy()),
    );

    Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .spawn()
        .map_err(|err| format!("failed to launch updater process: {err}"))?;

    println!("scheduled update to {version_text}");
    Ok(())
}

#[cfg(unix)]
fn replace_binary_in_place_unix(current_exe: &Path, replacement_binary: &Path) -> Result<(), String> {
    let replacement_path = current_exe.with_extension("new");
    std::fs::copy(replacement_binary, &replacement_path)
        .map_err(|err| format!("failed to stage replacement binary: {err}"))?;

    if let Ok(existing_meta) = std::fs::metadata(current_exe) {
        let mode = existing_meta.permissions().mode();
        let _ = std::fs::set_permissions(&replacement_path, std::fs::Permissions::from_mode(mode));
    }

    std::fs::rename(&replacement_path, current_exe).map_err(|err| {
        let _ = std::fs::remove_file(&replacement_path);
        format!("failed to replace current executable: {err}")
    })
}

#[cfg(unix)]
fn launch_updated_binary(exe: &Path) -> Result<i32, String> {
    let status = Command::new(exe)
        .arg("--version")
        .status()
        .map_err(|err| format!("updated binary installed but failed to launch: {err}"))?;

    Ok(status.code().unwrap_or(1))
}

fn make_temp_update_dir() -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock error: {err}"))?
        .as_nanos();
    let tmp = std::env::temp_dir().join(format!("fe203-update-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|err| format!("failed to create temp dir: {err}"))?;
    Ok(tmp)
}

fn download_release_asset(url: &str, output_path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let script = format!(
            "$ErrorActionPreference='Stop';Invoke-WebRequest -UseBasicParsing -Uri '{url}' -OutFile '{out}';",
            url = ps_single_quote_escape(url),
            out = ps_single_quote_escape(&output_path.to_string_lossy())
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
            .map_err(|err| format!("failed to download release asset: {err}"))?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("failed to download release asset: {}", stderr.trim()));
    }

    #[cfg(unix)]
    {
        let out = output_path.to_string_lossy().to_string();
        let curl = Command::new("curl")
            .args(["-fL", "-o", &out, url])
            .output();

        if let Ok(result) = curl {
            if result.status.success() {
                return Ok(());
            }
        }

        let wget = Command::new("wget").args(["-O", &out, url]).output();
        if let Ok(result) = wget {
            if result.status.success() {
                return Ok(());
            }
        }

        return Err("failed to download release asset (tried curl, then wget)".to_string());
    }
}

fn extract_archive(
    archive_path: &Path,
    destination_dir: &Path,
    archive_kind: ArchiveKind,
) -> Result<(), String> {
    match archive_kind {
        ArchiveKind::Zip => {
            #[cfg(not(windows))]
            {
                let _ = archive_path;
                let _ = destination_dir;
                return Err("zip archive extraction is unsupported on this platform".to_string());
            }

            #[cfg(windows)]
            {
                let script = format!(
                    "$ErrorActionPreference='Stop';Expand-Archive -Path '{zip}' -DestinationPath '{dest}' -Force;",
                    zip = ps_single_quote_escape(&archive_path.to_string_lossy()),
                    dest = ps_single_quote_escape(&destination_dir.to_string_lossy()),
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
                    .map_err(|err| format!("failed to extract archive: {err}"))?;

                if output.status.success() {
                    return Ok(());
                }

                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("failed to extract archive: {}", stderr.trim()))
            }
        }
        ArchiveKind::TarGz => {
            #[cfg(not(unix))]
            {
                let _ = archive_path;
                let _ = destination_dir;
                return Err("tar.gz extraction is unsupported on this platform".to_string());
            }

            #[cfg(unix)]
            {
                let output = Command::new("tar")
                    .arg("-xzf")
                    .arg(archive_path)
                    .arg("-C")
                    .arg(destination_dir)
                    .output()
                    .map_err(|err| format!("failed to run tar for extraction: {err}"))?;

                if output.status.success() {
                    return Ok(());
                }

                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("failed to extract archive: {}", stderr.trim()))
            }
        }
    }
}

fn find_file_recursively(root: &Path, file_name: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }

            if path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.eq_ignore_ascii_case(file_name))
                .unwrap_or(false)
            {
                return Some(path);
            }
        }
    }

    None
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SemverTriplet {
    major: u64,
    minor: u64,
    patch: u64,
}

#[derive(Clone, Copy, Debug)]
enum ArchiveKind {
    Zip,
    TarGz,
}

#[derive(Clone, Copy, Debug)]
struct TargetAssetSpec {
    suffix: &'static str,
    archive_kind: ArchiveKind,
    binary_name: &'static str,
}

#[derive(Debug)]
struct ReleaseInfo {
    version_text: String,
    version: SemverTriplet,
    asset_url: String,
    archive_kind: ArchiveKind,
    binary_name: &'static str,
}

impl ReleaseInfo {
    fn archive_file_name(&self) -> &'static str {
        match self.archive_kind {
            ArchiveKind::Zip => "fe203.zip",
            ArchiveKind::TarGz => "fe203.tar.gz",
        }
    }
}

fn latest_release_info() -> Result<ReleaseInfo, String> {
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

fn current_target_asset_spec() -> Option<TargetAssetSpec> {
    target_asset_spec(std::env::consts::OS, std::env::consts::ARCH)
}

fn target_asset_spec(os: &str, arch: &str) -> Option<TargetAssetSpec> {
    match (os, arch) {
        ("windows", "x86_64") => Some(TargetAssetSpec {
            suffix: "x86_64-pc-windows-msvc.zip",
            archive_kind: ArchiveKind::Zip,
            binary_name: "fe203.exe",
        }),
        ("linux", "x86_64") => Some(TargetAssetSpec {
            suffix: "x86_64-unknown-linux-gnu.tar.gz",
            archive_kind: ArchiveKind::TarGz,
            binary_name: "fe203",
        }),
        ("macos", "x86_64") => Some(TargetAssetSpec {
            suffix: "x86_64-apple-darwin.tar.gz",
            archive_kind: ArchiveKind::TarGz,
            binary_name: "fe203",
        }),
        _ => None,
    }
}

fn fetch_latest_release_json() -> Result<String, String> {
    #[cfg(windows)]
    {
        let repo = parse_github_repo_slug(env!("CARGO_PKG_REPOSITORY")).ok_or_else(|| {
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
        let repo = parse_github_repo_slug(env!("CARGO_PKG_REPOSITORY")).ok_or_else(|| {
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

fn parse_latest_release_json(json: &str, spec: TargetAssetSpec) -> Option<ReleaseInfo> {
    let tag = extract_json_string_field(json, "tag_name")?;
    let tag_no_v = tag.trim().trim_start_matches('v').to_string();
    let version = parse_semver_triplet(&tag_no_v)?;

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

fn find_asset_download_url(json: &str, names: &[&str]) -> Option<String> {
    for name in names {
        let mut cursor = 0usize;
        while let Some((asset_name, next_pos)) = find_next_key_value(json, "name", cursor) {
            if asset_name == *name {
                if let Some((download_url, _)) =
                    find_next_key_value(json, "browser_download_url", next_pos)
                {
                    return Some(download_url);
                }
            }
            cursor = next_pos;
        }
    }
    None
}

fn extract_json_string_field(json: &str, key: &str) -> Option<String> {
    find_next_key_value(json, key, 0).map(|(value, _)| value)
}

fn find_next_key_value(json: &str, key: &str, start: usize) -> Option<(String, usize)> {
    let key_pattern = format!("\"{}\"", key);
    let haystack = json.get(start..)?;
    let rel_idx = haystack.find(&key_pattern)?;
    let key_idx = start + rel_idx;

    let after_key = json.get(key_idx + key_pattern.len()..)?;
    let colon_rel = after_key.find(':')?;
    let mut value_start = key_idx + key_pattern.len() + colon_rel + 1;

    let bytes = json.as_bytes();
    while let Some(byte) = bytes.get(value_start) {
        if !byte.is_ascii_whitespace() {
            break;
        }
        value_start += 1;
    }

    let (value, next_idx) = parse_json_string_at(json, value_start)?;
    Some((value, next_idx))
}

fn parse_json_string_at(json: &str, start: usize) -> Option<(String, usize)> {
    let bytes = json.as_bytes();
    if *bytes.get(start)? != b'"' {
        return None;
    }

    let mut out = String::new();
    let mut idx = start + 1;
    while let Some(&byte) = bytes.get(idx) {
        match byte {
            b'\\' => {
                let escaped = *bytes.get(idx + 1)?;
                match escaped {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        // Keep unicode escapes verbatim for robustness in minimal parser.
                        let seq = json.get(idx + 2..idx + 6)?;
                        out.push_str("\\u");
                        out.push_str(seq);
                        idx += 4;
                    }
                    _ => return None,
                }
                idx += 2;
            }
            b'"' => return Some((out, idx + 1)),
            _ => {
                out.push(byte as char);
                idx += 1;
            }
        }
    }

    None
}

fn parse_semver_triplet(version_text: &str) -> Option<SemverTriplet> {
    let core = version_text
        .trim()
        .trim_start_matches('v')
        .split(['-', '+'])
        .next()?;

    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;

    if parts.next().is_some() {
        return None;
    }

    Some(SemverTriplet {
        major,
        minor,
        patch,
    })
}

fn parse_github_repo_slug(input: &str) -> Option<String> {
    let trimmed = input.trim().trim_end_matches('/');
    let suffix = trimmed.strip_prefix("https://github.com/")?;
    let mut parts = suffix.split('/');
    let owner = parts.next()?.trim();
    let repo = parts.next()?.trim();
    if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

#[cfg(windows)]
fn ps_single_quote_escape(input: &str) -> String {
    input.replace('\'', "''")
}

fn is_development_executable_path(path: &Path) -> bool {
    let parts = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect::<Vec<_>>();

    parts
        .windows(2)
        .any(|pair| pair[0] == "target" && (pair[1] == "debug" || pair[1] == "release"))
}

#[cfg(test)]
mod tests {
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
        let windows = target_asset_spec("windows", "x86_64").unwrap();
        assert_eq!(windows.suffix, "x86_64-pc-windows-msvc.zip");
        let linux = target_asset_spec("linux", "x86_64").unwrap();
        assert_eq!(linux.suffix, "x86_64-unknown-linux-gnu.tar.gz");
        let mac = target_asset_spec("macos", "x86_64").unwrap();
        assert_eq!(mac.suffix, "x86_64-apple-darwin.tar.gz");
        assert!(target_asset_spec("linux", "aarch64").is_none());
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

        let info = parse_latest_release_json(
            json,
            target_asset_spec("linux", "x86_64").expect("linux x86_64 spec"),
        )
        .unwrap();
        assert_eq!(info.version_text, "0.2.1");
        assert_eq!(
            info.asset_url,
            "https://example.invalid/fe203-linux.tar.gz".to_string()
        );
    }
}
