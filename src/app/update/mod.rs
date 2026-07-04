use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod json_scan;
mod platform;
mod release;
mod transfer;
mod types;

#[cfg(test)]
mod tests;

#[cfg(unix)]
use platform::{launch_updated_binary, replace_binary_in_place_unix};
#[cfg(windows)]
use platform::schedule_windows_replace_and_launch;
use release::latest_release_info;
use transfer::{download_release_asset, extract_archive, find_file_recursively};
use types::SemverTriplet;

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

    let exe = std::env::current_exe()
        .map_err(|err| format!("cannot locate current executable: {err}"))?;
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

fn make_temp_update_dir() -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock error: {err}"))?
        .as_nanos();
    let tmp = std::env::temp_dir().join(format!("fe203-update-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|err| format!("failed to create temp dir: {err}"))?;
    Ok(tmp)
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

fn is_development_executable_path(path: &Path) -> bool {
    let parts = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect::<Vec<_>>();

    parts
        .windows(2)
        .any(|pair| pair[0] == "target" && (pair[1] == "debug" || pair[1] == "release"))
}
